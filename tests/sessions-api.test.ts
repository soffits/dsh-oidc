import { describe, expect, it } from 'vitest'
import { AuditLog } from '../src/audit.js'
import { resolveConfig } from '../src/config.js'
import {
  REVOKE_PATH,
  SESSIONS_PATH,
  STATUS_PATH,
  sessionRoutes,
  statusView,
  type SessionAuthority,
  type SessionEntry,
  type StatusView,
} from '../src/sessions-api.js'
import { BrowserSessions, SESSION_COOKIE, type SessionView } from '../src/state.js'

const issuer = 'https://id.example'
const alice = { issuer, subject: 'alice', username: 'alice', groups: [] }
const bob = { issuer, subject: 'bob', email: 'bob@example.test', groups: [] }

const config = resolveConfig({
  issuer,
  clientId: 'client',
  publicOrigin: 'https://dsh.example',
  allowedEmails: ['bob@example.test', 'alice@example.test'],
  allowedSubjects: [{ issuer, subject: 'alice' }],
  requiredClaims: { tenant: ['t'] },
})

function setup() {
  const sessions = new BrowserSessions(3_600_000, 3_600_000, 100)
  const audit = new AuditLog({
    retentionMilliseconds: 1_000_000,
    maxEvents: 100,
    onError: () => undefined,
    emit: () => undefined,
  })
  const now = Date.now()
  const a1 = sessions.create(
    alice,
    { kind: 'browser', userAgent: 'Firefox', ip: '192.0.2.1' },
    now,
  )!
  const a2 = sessions.create(alice, { kind: 'browser' }, now - 10)!
  const b1 = sessions.create(bob, { kind: 'browser' }, now - 5)!
  const authority: SessionAuthority = {
    sessionFromCookie: (cookie) => {
      const value = cookie?.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`, 'u'))?.[1]
      return sessions.read(value)
    },
    listSessions: () => sessions.list(),
    revokeSession: async (id: string, actor: SessionView) => {
      const revoked = await sessions.revoke(id)
      if (revoked !== undefined)
        audit.record({
          type: 'session-revoked',
          session: id,
          by: { issuer, subject: actor.principal.subject },
        })
      return revoked
    },
    audit,
  }
  const routes = sessionRoutes(authority, () => statusView(config, ['DSH_OIDC_ISSUER'], []))
  const call = (path: string, init: RequestInit & { cookie?: string } = {}) => {
    const route = routes.find((candidate) => candidate.path === path)!
    const headers = new Headers(init.headers)
    if (init.cookie !== undefined) headers.set('cookie', `${SESSION_COOKIE}=${init.cookie}`)
    return route.fetch(new Request(`http://dsh.internal${path}`, { ...init, headers }))
  }
  const revoke = (cookie: string, body: unknown, headers: Record<string, string> = {}) =>
    call(REVOKE_PATH, {
      method: 'POST',
      cookie,
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(body),
    })
  return { sessions, audit, call, revoke, a1, a2, b1 }
}

describe('sessions endpoints', () => {
  it('lists the caller first, then their other sessions, then everyone else', async () => {
    const { call, a1, a2, b1 } = setup()
    const response = await call(SESSIONS_PATH, { cookie: a2.value })
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
    const { sessions } = (await response.json()) as { sessions: SessionEntry[] }
    expect(sessions.map(({ id, current, mine }) => [id, current, mine])).toEqual([
      [a2.id, true, true],
      [a1.id, false, true],
      [b1.id, false, false],
    ])
    expect(sessions[1]).toMatchObject({ name: 'alice', userAgent: 'Firefox', ip: '192.0.2.1' })
    expect(sessions[2]).toMatchObject({ name: 'bob@example.test', email: 'bob@example.test' })
    expect(JSON.stringify(sessions)).not.toMatch(/csrf|policy/u)
    expect(JSON.stringify(sessions)).not.toContain(a1.value)
  })

  it('answers nothing without a live session or to a cross-site request', async () => {
    const { call, a1 } = setup()
    for (const path of [SESSIONS_PATH, STATUS_PATH]) {
      expect((await call(path)).status).toBe(401)
      expect((await call(path, { cookie: 'x'.repeat(43) })).status).toBe(401)
      expect(
        (await call(path, { cookie: a1.value, headers: { 'sec-fetch-site': 'cross-site' } }))
          .status,
      ).toBe(403)
      expect(
        (await call(path, { cookie: a1.value, headers: { 'sec-fetch-site': 'same-origin' } }))
          .status,
      ).toBe(200)
    }
  })

  it("revokes anyone's session by id, durably ends it, and records who did it", async () => {
    const { call, revoke, audit, a1, b1 } = setup()
    const response = await revoke(a1.value, { id: b1.id })
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ revoked: [b1.id] })
    expect((await call(SESSIONS_PATH, { cookie: b1.value })).status).toBe(401)
    expect(audit.recent(1)[0]).toMatchObject({ session: b1.id, by: { subject: 'alice' } })
    expect((await revoke(a1.value, { id: b1.id })).status).toBe(404)
  })

  it('signs the caller out everywhere else but keeps this session and other people', async () => {
    const { call, revoke, a1, a2, b1 } = setup()
    const response = await revoke(a1.value, { others: true })
    expect(await response.json()).toEqual({ revoked: [a2.id] })
    const { sessions } = (await (await call(SESSIONS_PATH, { cookie: a1.value })).json()) as {
      sessions: SessionEntry[]
    }
    expect(sessions.map(({ id }) => id)).toEqual([a1.id, b1.id])
  })

  it('refuses malformed, cross-site, unauthenticated and self revokes', async () => {
    const { revoke, call, a1, b1 } = setup()
    expect((await revoke(a1.value, { id: a1.id })).status).toBe(409)
    for (const body of [{}, { id: 'short' }, { id: b1.id, others: true }, { others: 'yes' }, []])
      expect((await revoke(a1.value, body)).status, JSON.stringify(body)).toBe(400)
    expect((await revoke(a1.value, { id: b1.id }, { 'content-type': 'text/plain' })).status).toBe(
      400,
    )
    expect(
      (
        await call(REVOKE_PATH, {
          method: 'POST',
          cookie: a1.value,
          headers: { 'content-type': 'application/json' },
          body: '{not json',
        })
      ).status,
    ).toBe(400)
    expect((await revoke(a1.value, { id: b1.id }, { 'sec-fetch-site': 'same-site' })).status).toBe(
      403,
    )
    expect((await revoke('y'.repeat(43), { id: b1.id })).status).toBe(401)
    expect((await call(SESSIONS_PATH, { cookie: b1.value })).status).toBe(200)
  })

  it('summarizes the configuration without the client secret', async () => {
    const { call, a1 } = setup()
    const status = (await (await call(STATUS_PATH, { cookie: a1.value })).json()) as StatusView
    expect(status).toMatchObject({
      mode: 'forward-auth',
      issuer,
      clientId: 'client',
      publicOrigin: 'https://dsh.example',
      policy: {
        subjects: 1,
        emails: ['alice@example.test', 'bob@example.test'],
        groups: [],
        groupMode: 'any',
        requiredClaims: ['tenant'],
        anyUser: false,
      },
      requireSessionOnApi: true,
      environment: ['DSH_OIDC_ISSUER'],
    })
    const anyUser = statusView(
      resolveConfig({
        issuer,
        clientId: 'c',
        publicOrigin: 'https://dsh.example',
        allowAnyUser: true,
        clientSecretRef: 'SECRET_REF',
      }),
      [],
      [],
    )
    expect(anyUser.policy.anyUser).toBe(true)
    expect(JSON.stringify(anyUser)).not.toContain('SECRET_REF')
  })
})
