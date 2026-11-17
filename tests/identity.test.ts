import type { IncomingMessage, ServerResponse } from 'node:http'
import { afterEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import * as connectionPlugin from '@deepseek-ai/dsh-client-connection'
import { WebServer } from '@deepseek-ai/dsh-host-webserver'
import {
  REQUEST_IDENTITY_SERVICE,
  applyRequestIdentity,
  identityOf,
  type RequestIdentityService,
} from '../src/identity.js'
import type { Principal } from '../src/policy.js'
import { SESSION_COOKIE, readCookie } from '../src/state.js'

const ISSUER = 'https://id.example'
const ALICE: Principal = {
  issuer: ISSUER,
  subject: '6f1c2a3b-0000-4000-8000-000000000001',
  username: 'alice',
  displayName: 'Alice',
  groups: [],
}
const BOB: Principal = {
  issuer: ISSUER,
  subject: '6f1c2a3b-0000-4000-8000-000000000002',
  email: 'bob@example.test',
  groups: [],
}

const SESSIONS: Record<string, Principal> = { 'token-alice': ALICE, 'token-bob': BOB }
const principalOf = (req: IncomingMessage): Principal | undefined => {
  const value = readCookie(req.headers.cookie, SESSION_COOKIE)
  return value === undefined ? undefined : SESSIONS[value]
}

function fakeRequest(cookie?: string): IncomingMessage {
  return { headers: cookie === undefined ? {} : { cookie } } as IncomingMessage
}

function apiRequest(ctx: Context, cookie: string | undefined, body: () => Promise<void>) {
  return ctx.waterfall('connection/request', fakeRequest(cookie), {} as ServerResponse, body)
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0))

describe('identityOf', () => {
  it('names the person by username, then display name, then email', () => {
    expect(identityOf(ALICE)).toEqual({
      provider: 'oidc',
      issuer: ISSUER,
      id: ALICE.subject,
      name: 'alice',
    })
    expect(identityOf(BOB).name).toBe('bob@example.test')
    expect(identityOf({ issuer: ISSUER, subject: 'x', groups: [] })).not.toHaveProperty('name')
  })
})

describe('applyRequestIdentity', () => {
  function host(): { ctx: Context; identity: RequestIdentityService } {
    const ctx = new Context()
    return { ctx, identity: applyRequestIdentity(ctx, principalOf) }
  }

  it('reads the verified person inside the request, across awaits', async () => {
    const { ctx, identity } = host()
    const seen: unknown[] = []
    await apiRequest(ctx, `${SESSION_COOKIE}=token-alice`, async () => {
      seen.push(identity.current()?.id)
      await tick()
      seen.push(identity.current()?.id)
    })
    expect(seen).toEqual([ALICE.subject, ALICE.subject])
  })

  it('is null outside a request and for a request without an OIDC session', async () => {
    const { ctx, identity } = host()
    expect(identity.current()).toBeNull()
    let inside: unknown = 'unset'
    await apiRequest(ctx, undefined, async () => {
      inside = identity.current()
    })
    expect(inside).toBeNull()
  })

  it('keeps concurrent requests apart', async () => {
    const { ctx, identity } = host()
    const seen: Record<string, unknown> = {}
    await Promise.all([
      apiRequest(ctx, `${SESSION_COOKIE}=token-alice`, async () => {
        await tick()
        seen.alice = identity.current()?.id
      }),
      apiRequest(ctx, `${SESSION_COOKIE}=token-bob`, async () => {
        seen.bob = identity.current()?.id
        await tick()
        seen.bobLater = identity.current()?.id
      }),
    ])
    expect(seen).toEqual({ alice: ALICE.subject, bob: BOB.subject, bobLater: BOB.subject })
  })

  it('is null in work the request started once the request has settled', async () => {
    const { ctx, identity } = host()
    let later: Promise<unknown> = Promise.resolve()
    await apiRequest(ctx, `${SESSION_COOKIE}=token-alice`, async () => {
      later = new Promise((resolve) => setTimeout(() => resolve(identity.current()), 10))
    })
    expect(await later).toBeNull()
  })
})

describe('with the real DSH Connection and web server', () => {
  let root: Context | undefined
  afterEach(async () => {
    await root?.fiber.dispose()
    root = undefined
  })

  it('a plugin Fetch route under /api sees the identity of the browser that called it', async () => {
    root = new Context()
    const records = new Map<string, unknown>()
    root.provide('credentials')
    root.set('credentials', {
      async modifyRecord(key: string, mutate: (current: unknown) => Promise<unknown>) {
        const next = await mutate(records.get(key))
        if (next !== undefined) records.set(key, next)
        return records.get(key)
      },
    })
    await root.plugin(WebServer, { host: '127.0.0.1', port: 0 })
    await root.plugin(connectionPlugin, {})
    root.provide(REQUEST_IDENTITY_SERVICE, applyRequestIdentity(root, principalOf))
    const ctx = root
    ctx.connection.fetch.register({
      path: '/api/example/whoami',
      methods: ['GET'],
      requestBody: 'buffered',
      fetch: async () => {
        await tick()
        const identity = ctx.get(REQUEST_IDENTITY_SERVICE)!.current()
        return Response.json({ id: identity?.id ?? null })
      },
    })
    ctx.webServer.registerFallback((req, res) => {
      if (ctx.connection.authorizeIndex(req, res)) res.end('index')
    })
    const origin = ctx.webServer.getOrigin()
    const bootstrap = await fetch(ctx.connection.authenticatedUrl(`${origin}/`), {
      redirect: 'manual',
    })
    const nativeCookie = (bootstrap.headers.get('set-cookie') ?? '').split(';', 1)[0] ?? ''
    expect(nativeCookie).toMatch(/^dsh-auth-/u)

    const whoami = async (oidc?: string) => {
      const response = await fetch(`${origin}/api/example/whoami`, {
        headers: {
          cookie: oidc === undefined ? nativeCookie : `${nativeCookie}; ${SESSION_COOKIE}=${oidc}`,
        },
      })
      expect(response.status).toBe(200)
      return ((await response.json()) as { id: string | null }).id
    }
    expect(await whoami('token-alice')).toBe(ALICE.subject)
    expect(await whoami('token-bob')).toBe(BOB.subject)
    expect(await whoami()).toBeNull()
    expect(await whoami('token-unknown')).toBeNull()
  })
})
