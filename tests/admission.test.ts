import { createHash } from 'node:crypto'
import { PassThrough, Readable } from 'node:stream'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CLIENT_IP_HEADER,
  OidcAdmission,
  type AdmissionLogger,
  type CredentialResolver,
} from '../src/admission.js'
import { resolveConfig } from '../src/config.js'
import {
  OidcValidationError,
  type AuthorizationStart,
  type CallbackChecks,
  type OidcProtocol,
} from '../src/oidc.js'
import { SESSION_COOKIE, TRANSACTION_COOKIE } from '../src/state.js'

interface CapturedResponse {
  status?: number
  headers?: Record<string, string | readonly string[]>
  body?: string
}

function response(): { value: ServerResponse; captured: CapturedResponse } {
  const captured: CapturedResponse = {}
  const value = {
    writeHead(status: number, headers?: Record<string, string | readonly string[]>) {
      captured.status = status
      if (headers !== undefined) captured.headers = headers
      return value
    },
    end(body?: string) {
      if (body !== undefined) captured.body = body
      return value
    },
  }
  return { value: value as ServerResponse, captured }
}

function request(
  method: string,
  url: string,
  headers: Record<string, string | string[]> = {},
  body?: string,
  remoteAddress = '127.0.0.1',
): IncomingMessage {
  const value = Readable.from(body === undefined ? [] : [Buffer.from(body)])
  Object.assign(value, {
    method,
    url,
    headers: { host: 'dsh.example', [CLIENT_IP_HEADER]: '192.0.2.10', ...headers },
    socket: { remoteAddress },
  })
  return value as IncomingMessage
}

function cookieFrom(headers: CapturedResponse['headers'], name: string): string {
  const raw = headers?.['set-cookie']
  const values = typeof raw === 'string' ? [raw] : raw
  const found = values?.find((value) => value.startsWith(`${name}=`))
  if (found === undefined) throw new Error(`missing ${name}`)
  return found.split(';', 1)[0] ?? ''
}

class FakeProtocol implements OidcProtocol {
  startError = false
  callbackError = false
  claims: Readonly<Record<string, unknown>> = {
    iss: 'https://id.example/issuer',
    sub: 'allowed',
  }
  callbackChecks?: CallbackChecks
  logout = new URL('https://id.example/logout')

  async start(secret: string | undefined): Promise<AuthorizationStart> {
    expect(secret).toBe('rotating-secret')
    if (this.startError) throw new Error('secret-bearing provider error')
    return {
      url: new URL('https://id.example/authorize?client_id=client'),
      verifier: 'verifier',
      nonce: 'nonce',
    }
  }

  async callback(
    secret: string | undefined,
    checks: CallbackChecks,
  ): Promise<Readonly<Record<string, unknown>>> {
    expect(secret).toBe('rotating-secret')
    this.callbackChecks = checks
    if (this.callbackError) throw new Error('token-bearing provider error')
    return this.claims
  }

  async logoutUrl(): Promise<URL | undefined> {
    return this.logout
  }
}

const config = resolveConfig({
  issuer: 'https://id.example/issuer',
  clientId: 'client',
  clientSecretRef: 'OIDC_SECRET',
  publicOrigin: 'https://dsh.example',
  allowedSubjects: [{ issuer: 'https://id.example/issuer', subject: 'allowed' }],
})

function harness(): {
  admission: OidcAdmission
  protocol: FakeProtocol
  messages: string[]
} {
  const protocol = new FakeProtocol()
  const credentials: CredentialResolver = {
    resolve: vi.fn(async () => ({ value: 'rotating-secret', source: 'test' })),
  }
  const messages: string[] = []
  const logger: AdmissionLogger = {
    info: (message) => messages.push(message),
    warn: (message) => messages.push(message),
  }
  return {
    admission: new OidcAdmission(
      config,
      credentials,
      { authenticatedUrl: (origin) => `${origin}?token=native-bootstrap` },
      protocol,
      logger,
    ),
    protocol,
    messages,
  }
}

async function login(
  admission: OidcAdmission,
): Promise<{ cookie: string; state: string; captured: CapturedResponse }> {
  const res = response()
  await admission.login(request('GET', '/auth/login'), res.value)
  const cookie = cookieFrom(res.captured.headers, TRANSACTION_COOKIE)
  const state = new URL(String(res.captured.headers?.location)).searchParams.get('state')
  if (state === null) throw new Error('missing state')
  return { cookie, state, captured: res.captured }
}

beforeEach(() => vi.restoreAllMocks())

describe('OIDC route admission', () => {
  it('serves the bundled sign-in page to navigations and keeps the plain 401 for API clients', async () => {
    const { admission } = harness()

    const browser = response()
    admission.check(
      request('GET', '/auth/check', { accept: 'text/html,application/xhtml+xml' }),
      browser.value,
    )
    expect(browser.captured.status).toBe(303)
    expect(browser.captured.headers?.location).toBe('/auth/signin')

    const fetchClient = response()
    admission.check(request('GET', '/auth/check', { accept: '*/*' }), fetchClient.value)
    expect(fetchClient.captured.status).toBe(401)
    expect(fetchClient.captured.body).toBe('unauthorized\n')

    const noSecFetchNoHtml = response()
    admission.check(
      request('GET', '/auth/check', { accept: 'application/json' }),
      noSecFetchNoHtml.value,
    )
    expect(noSecFetchNoHtml.captured.status).toBe(401)

    const head = response()
    admission.check(request('HEAD', '/auth/check', { accept: 'text/html' }), head.value)
    expect(head.captured.status).toBe(401)
    expect(head.captured.body).toBeUndefined()

    const page = response()
    admission.signin(request('GET', '/auth/signin'), page.value)
    expect(page.captured.status).toBe(200)
    expect(page.captured.headers?.['content-type']).toContain('text/html')
    expect(String(page.captured.body)).toContain('/auth/login')

    const badHost = response()
    admission.signin(request('GET', '/auth/signin', { host: 'evil.example' }), badHost.value)
    expect(badHost.captured.status).toBe(403)

    const method = response()
    admission.signin(request('POST', '/auth/signin'), method.value)
    expect(method.captured).toMatchObject({ status: 405, headers: { allow: 'GET, HEAD' } })
  })

  it("lets the sign-in page's own style through its CSP and nothing else", () => {
    const { admission } = harness()
    const page = response()
    admission.signin(request('GET', '/auth/signin'), page.value)
    const policy = new Map(
      String(page.captured.headers?.['content-security-policy'])
        .split(';')
        .map((directive) => directive.trim().split(/\s+/u))
        .map(([name, ...values]) => [name!, values]),
    )
    expect([...policy.keys()].sort()).toEqual([
      'base-uri',
      'default-src',
      'frame-ancestors',
      'style-src',
    ])
    expect(policy.get('default-src')).toEqual(["'none'"])
    const styles = [...String(page.captured.body).matchAll(/<style>([^<]*)<\/style>/gu)]
    expect(styles).toHaveLength(1)
    const digest = createHash('sha256').update(styles[0]![1]!).digest('base64')
    expect(policy.get('style-src')).toEqual([`'sha256-${digest}'`])
  })

  it('sends signed-out navigations straight to the provider with directLogin', async () => {
    const direct = resolveConfig({
      issuer: 'https://id.example/issuer',
      clientId: 'client',
      publicOrigin: 'https://dsh.example',
      allowedSubjects: [{ issuer: 'https://id.example/issuer', subject: 'allowed' }],
      directLogin: true,
    })
    const admission = new OidcAdmission(
      direct,
      { resolve: vi.fn(async () => undefined) },
      { authenticatedUrl: (origin) => origin },
      new FakeProtocol(),
      { info: () => undefined, warn: () => undefined },
    )
    const navigation = response()
    admission.check(
      request('GET', '/auth/check', { accept: 'text/html,application/xhtml+xml' }),
      navigation.value,
    )
    expect(navigation.captured.status).toBe(303)
    expect(navigation.captured.headers?.location).toBe('/auth/login?nav=1')

    const api = response()
    admission.check(request('GET', '/auth/check', { accept: '*/*' }), api.value)
    expect(api.captured.status).toBe(401)
  })

  it('passes the manifest and app icons without a session, as the proxy names them', () => {
    const { admission } = harness()
    const ask = (forwarded: Record<string, string>, remoteAddress = '127.0.0.1') => {
      const res = response()
      admission.check(
        request('GET', '/auth/check', { accept: '*/*', ...forwarded }, undefined, remoteAddress),
        res.value,
      )
      return res.captured.status
    }
    const asProxy = (method: string, uri: string) => ({
      'x-forwarded-method': method,
      'x-forwarded-uri': uri,
    })
    expect(ask(asProxy('GET', '/manifest.webmanifest'))).toBe(204)
    expect(ask(asProxy('HEAD', '/apple-touch-icon.png'))).toBe(204)
    expect(ask(asProxy('GET', '/icon-maskable-512.png?v=3'))).toBe(204)
    for (const [method, uri] of [
      ['POST', '/manifest.webmanifest'],
      ['GET', '/'],
      ['GET', '/favicon.svg'],
      ['GET', '/api/notify-inbox/sw.js'],
      ['GET', '/plugins/events'],
      ['GET', '/connect?token=x'],
      ['GET', '/icon-192.png/../../api/x'],
      ['GET', 'https://dsh.example/manifest.webmanifest'],
    ])
      expect(ask(asProxy(method!, uri!)), `${method!} ${uri!}`).toBe(401)
    // Without the method the proxy always sends, nothing is assumed.
    expect(ask({ 'x-forwarded-uri': '/manifest.webmanifest' })).toBe(401)
    // A client that reaches the check directly can't name a public file.
    expect(ask(asProxy('GET', '/manifest.webmanifest'), '198.51.100.7')).toBe(401)
  })

  it('answers HEAD login without creating transaction state', async () => {
    const { admission, protocol } = harness()
    const start = vi.spyOn(protocol, 'start')
    const res = response()
    await admission.login(request('HEAD', '/auth/login'), res.value)
    expect(res.captured).toMatchObject({ status: 204 })
    expect(res.captured.headers?.['set-cookie']).toBeUndefined()
    expect(start).not.toHaveBeenCalled()

    const mapped = response()
    await admission.login(
      request('HEAD', '/auth/login', {}, undefined, '::ffff:127.0.0.1'),
      mapped.value,
    )
    expect(mapped.captured.status).toBe(204)
  })

  it('by default trusts one proxy-set client IP only from loopback and rejects spoofed or malformed values', async () => {
    const { admission } = harness()
    for (const req of [
      request('GET', '/auth/login', { [CLIENT_IP_HEADER]: '192.0.2.10' }, undefined, '10.0.0.9'),
      request('GET', '/auth/login', { [CLIENT_IP_HEADER]: '192.0.2.10, 198.51.100.4' }),
      request('GET', '/auth/login', { [CLIENT_IP_HEADER]: ['192.0.2.10', '198.51.100.4'] }),
      request('GET', '/auth/login', { [CLIENT_IP_HEADER]: 'not-an-ip' }),
      request('GET', '/auth/login', { [CLIENT_IP_HEADER]: '' }),
    ]) {
      const res = response()
      await admission.login(req, res.value)
      expect(res.captured.status).toBe(403)
    }
  })

  it('trusts the client IP header from a configured proxy network and nowhere else', async () => {
    const protocol = new FakeProtocol()
    const proxied = new OidcAdmission(
      resolveConfig({
        issuer: 'https://id.example/issuer',
        clientId: 'client',
        clientSecretRef: 'OIDC_SECRET',
        publicOrigin: 'https://dsh.example',
        allowedSubjects: [{ issuer: 'https://id.example/issuer', subject: 'allowed' }],
        trustedProxies: ['172.18.0.0/16', 'fd00::5'],
      }),
      { resolve: vi.fn(async () => ({ value: 'rotating-secret', source: 'test' })) },
      { authenticatedUrl: (origin) => origin },
      protocol,
      { info: () => undefined, warn: () => undefined },
    )
    const statusFrom = async (peer: string, headers: Record<string, string> = {}) => {
      const res = response()
      await proxied.login(request('GET', '/auth/login', headers, undefined, peer), res.value)
      return res.captured.status
    }
    // Docker-network proxy, IPv4-mapped form of it, and an exact IPv6 proxy are trusted.
    expect(await statusFrom('172.18.0.3')).toBe(303)
    expect(await statusFrom('::ffff:172.18.0.3')).toBe(303)
    expect(await statusFrom('fd00::5')).toBe(303)
    // Loopback is no longer trusted once the list is replaced, and other peers never are.
    expect(await statusFrom('127.0.0.1')).toBe(403)
    expect(await statusFrom('172.19.0.3')).toBe(403)
    expect(await statusFrom('fd00::6')).toBe(403)
    // A trusted proxy still has to send exactly one valid address.
    expect(await statusFrom('172.18.0.3', { [CLIENT_IP_HEADER]: 'not-an-ip' })).toBe(403)
    expect(await statusFrom('172.18.0.3', { [CLIENT_IP_HEADER]: '192.0.2.1, 192.0.2.2' })).toBe(403)
  })

  it('rate limits one client without denying a distinct client', async () => {
    const { admission } = harness()
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const admitted = response()
      await admission.login(
        request('GET', '/auth/login', { [CLIENT_IP_HEADER]: '192.0.2.20' }),
        admitted.value,
      )
      expect(admitted.captured.status).toBe(303)
    }
    const limited = response()
    await admission.login(
      request('GET', '/auth/login', { [CLIENT_IP_HEADER]: '192.0.2.20' }),
      limited.value,
    )
    expect(limited.captured.status).toBe(429)

    const independent = response()
    await admission.login(
      request('GET', '/auth/login', { [CLIENT_IP_HEADER]: '198.51.100.30' }),
      independent.value,
    )
    expect(independent.captured.status).toBe(303)
  })

  it('fails closed when the configured client credential is missing', async () => {
    const { protocol, messages } = harness()
    const admission = new OidcAdmission(
      config,
      { resolve: vi.fn(async () => undefined) },
      { authenticatedUrl: (origin) => origin },
      protocol,
      { info: (message) => messages.push(message), warn: (message) => messages.push(message) },
    )
    const res = response()
    await admission.login(request('GET', '/auth/login'), res.value)
    expect(res.captured).toMatchObject({ status: 503, body: 'authentication unavailable\n' })
    expect(protocol.callbackChecks).toBeUndefined()
    expect(messages.join('\n')).toMatch(
      /login failed correlation=[0-9a-f]{16} reason=OidcValidationError OIDC_CLIENT_SECRET_UNAVAILABLE$/mu,
    )
  })

  it('logs why a callback failed without the error text', async () => {
    const reasons: Array<[unknown, string]> = [
      [new OidcValidationError('OIDC_AZP_MISMATCH'), 'OidcValidationError OIDC_AZP_MISMATCH'],
      [
        Object.assign(new Error('provider said code=abc token=xyz'), {
          name: 'ResponseBodyError',
          code: 'OAUTH_RESPONSE_BODY_ERROR',
          error: 'invalid_grant',
          status: 400,
        }),
        'ResponseBodyError OAUTH_RESPONSE_BODY_ERROR error=invalid_grant status=400',
      ],
      [
        new TypeError('fetch failed https://id.example/token?code=abc', {
          cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
        }),
        'TypeError <- Error ECONNREFUSED',
      ],
    ]
    for (const [error, reason] of reasons) {
      const { admission, protocol, messages } = harness()
      protocol.callback = async () => {
        throw error
      }
      const started = await login(admission)
      const res = response()
      await admission.callback(
        request('GET', `/auth/callback?code=abc&state=${started.state}`, {
          cookie: started.cookie,
        }),
        res.value,
      )
      expect(res.captured.status).toBe(400)
      const logged = messages.find((message) => message.includes('callback failed'))
      expect(logged).toMatch(new RegExp(`correlation=[0-9a-f]{16} reason=${reason}$`, 'u'))
      expect(logged).not.toMatch(/abc|xyz|fetch failed|provider said/u)
    }
  })

  it('runs one-use authorization and bootstraps the unchanged native DSH connection', async () => {
    const { admission, protocol, messages } = harness()
    const started = await login(admission)
    expect(started.captured.status).toBe(303)
    expect(started.captured.headers?.['cache-control']).toBe('no-store')
    expect(started.cookie).toContain(`${TRANSACTION_COOKIE}=`)
    expect(String(started.captured.headers?.['set-cookie'])).toContain(
      'HttpOnly; Secure; SameSite=Lax',
    )

    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?code=code&state=${started.state}`, { cookie: started.cookie }),
      callback.value,
    )
    // A same-origin page, not a redirect, so the follow-up navigation is
    // same-site and the browser sends DSH's SameSite=Strict native cookie.
    expect(callback.captured.status).toBe(200)
    expect(callback.captured.headers?.location).toBeUndefined()
    expect(String(callback.captured.body)).toContain(
      'http-equiv="refresh" content="0;url=https://dsh.example/?token=native-bootstrap"',
    )
    const session = cookieFrom(callback.captured.headers, SESSION_COOKIE)
    expect(session).not.toContain('allowed')
    expect(protocol.callbackChecks).toMatchObject({
      verifier: 'verifier',
      nonce: 'nonce',
      state: started.state,
    })

    const check = response()
    admission.check(request('GET', '/auth/check', { cookie: session }), check.value)
    expect(check.captured.status).toBe(204)

    const restarted = response()
    harness().admission.check(request('GET', '/auth/check', { cookie: session }), restarted.value)
    expect(restarted.captured.status).toBe(401)

    const replay = response()
    await admission.callback(
      request('GET', `/auth/callback?code=code&state=${started.state}`, { cookie: started.cookie }),
      replay.value,
    )
    expect(replay.captured.status).toBe(400)
    expect(messages.join('\n')).not.toMatch(/rotating-secret|code=|allowed|nonce|verifier/u)
  })

  it('serves the signed-in profile and logout CSRF only to a live same-origin session', async () => {
    const { admission, protocol } = harness()
    protocol.claims = {
      iss: 'https://id.example/issuer',
      sub: 'allowed',
      name: 'Synthetic Operator',
      preferred_username: 'operator',
      email: 'operator@example.test',
      picture: 'https://id.example/avatar.png',
    }
    const started = await login(admission)
    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?code=code&state=${started.state}`, { cookie: started.cookie }),
      callback.value,
    )
    const session = cookieFrom(callback.captured.headers, SESSION_COOKIE)

    // The sender context reads the same verified session, and nothing else.
    expect(
      admission.principalOf(request('POST', '/api/session/prompt', { cookie: session })),
    ).toMatchObject({
      issuer: 'https://id.example/issuer',
      subject: 'allowed',
      username: 'operator',
    })
    expect(admission.principalOf(request('POST', '/api/session/prompt'))).toBeUndefined()
    expect(
      harness().admission.principalOf(request('POST', '/api/x', { cookie: session })),
    ).toBeUndefined()

    const anonymous = response()
    admission.session(request('GET', '/_dsh-oidc/session'), anonymous.value)
    expect(anonymous.captured).toMatchObject({ status: 401, body: 'unauthorized\n' })

    const stale = response()
    harness().admission.session(
      request('GET', '/_dsh-oidc/session', { cookie: session }),
      stale.value,
    )
    expect(stale.captured.status).toBe(401)

    const crossSite = response()
    admission.session(
      request('GET', '/_dsh-oidc/session', { cookie: session, 'sec-fetch-site': 'cross-site' }),
      crossSite.value,
    )
    expect(crossSite.captured.status).toBe(403)

    const badHost = response()
    admission.session(
      request('GET', '/_dsh-oidc/session', { cookie: session, host: 'evil.example' }),
      badHost.value,
    )
    expect(badHost.captured.status).toBe(403)

    const post = response()
    admission.session(request('POST', '/_dsh-oidc/session', { cookie: session }), post.value)
    expect(post.captured).toMatchObject({ status: 405, headers: { allow: 'GET' } })

    const ok = response()
    admission.session(
      request('GET', '/_dsh-oidc/session', { cookie: session, 'sec-fetch-site': 'same-origin' }),
      ok.value,
    )
    expect(ok.captured.status).toBe(200)
    expect(ok.captured.headers?.['cache-control']).toBe('no-store')
    const body = JSON.parse(String(ok.captured.body)) as Record<string, unknown>
    expect(Object.keys(body).sort()).toEqual(['csrf', 'email', 'name', 'picture', 'username'])
    expect(body).toMatchObject({
      name: 'Synthetic Operator',
      username: 'operator',
      email: 'operator@example.test',
      picture: 'https://id.example/avatar.png',
    })
    expect(String(body.csrf)).toMatch(/^[A-Za-z0-9_-]{43}$/u)
    // No subject, issuer, groups, session bearer, or provider token reaches the browser.
    const text = String(ok.captured.body)
    expect(text).not.toMatch(/allowed|issuer|native-bootstrap|rotating-secret|nonce|verifier/u)
    expect(text).not.toContain(session.split('=')[1])

    // The CSRF value it hands out is the one logout accepts.
    const logout = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie: session,
          origin: 'https://dsh.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        `csrf=${String(body.csrf)}`,
      ),
      logout.value,
    )
    expect(logout.captured.status).toBe(303)
    const after = response()
    admission.session(request('GET', '/_dsh-oidc/session', { cookie: session }), after.value)
    expect(after.captured.status).toBe(401)
  })

  it('omits profile fields the provider did not send or sent unsafely', async () => {
    const { admission, protocol } = harness()
    protocol.claims = {
      iss: 'https://id.example/issuer',
      sub: 'allowed',
      picture: 'javascript:alert(1)',
      email: 42,
    }
    const started = await login(admission)
    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?code=code&state=${started.state}`, { cookie: started.cookie }),
      callback.value,
    )
    const session = cookieFrom(callback.captured.headers, SESSION_COOKIE)
    const ok = response()
    admission.session(request('GET', '/_dsh-oidc/session', { cookie: session }), ok.value)
    expect(Object.keys(JSON.parse(String(ok.captured.body)) as object)).toEqual(['csrf'])
  })

  it('fails closed for host, method, missing session, wrong state, provider failure, and policy denial', async () => {
    const { admission, protocol } = harness()
    const badHost = response()
    await admission.login(request('GET', '/auth/login', { host: 'evil.example' }), badHost.value)
    expect(badHost.captured.status).toBe(403)

    const forgedForwarded = response()
    await admission.login(
      request('GET', '/auth/login', { host: 'evil.example', 'x-forwarded-host': 'dsh.example' }),
      forgedForwarded.value,
    )
    expect(forgedForwarded.captured.status).toBe(403)

    const crossSite = response()
    await admission.login(
      request('GET', '/auth/login', { 'sec-fetch-site': 'cross-site' }),
      crossSite.value,
    )
    expect(crossSite.captured.status).toBe(403)

    const method = response()
    await admission.login(request('POST', '/auth/login'), method.value)
    expect(method.captured).toMatchObject({ status: 405, headers: { allow: 'GET, HEAD' } })

    const check = response()
    admission.check(request('HEAD', '/auth/check'), check.value)
    expect(check.captured.status).toBe(401)
    expect(check.captured.body).toBeUndefined()

    const first = await login(admission)
    const wrongState = response()
    await admission.callback(
      request('GET', '/auth/callback?state=wrong', { cookie: first.cookie }),
      wrongState.value,
    )
    expect(wrongState.captured.status).toBe(400)

    const duplicate = await login(admission)
    const duplicateState = response()
    await admission.callback(
      request('GET', `/auth/callback?state=${duplicate.state}&state=${duplicate.state}`, {
        cookie: duplicate.cookie,
      }),
      duplicateState.value,
    )
    expect(duplicateState.captured.status).toBe(400)

    protocol.startError = true
    const failedStart = response()
    await admission.login(request('GET', '/auth/login'), failedStart.value)
    expect(failedStart.captured).toMatchObject({
      status: 503,
      body: 'authentication unavailable\n',
    })

    protocol.startError = false
    protocol.claims = { iss: config.issuerId, sub: 'denied' }
    const second = await login(admission)
    const denied = response()
    await admission.callback(
      request('GET', `/auth/callback?state=${second.state}`, { cookie: second.cookie }),
      denied.value,
    )
    expect(denied.captured.status).toBe(403)
  })

  it('admits a bare-origin issuer whose ID token iss has no trailing slash', async () => {
    const bare = resolveConfig({
      issuer: 'https://id.example',
      clientId: 'client',
      clientSecretRef: 'OIDC_SECRET',
      publicOrigin: 'https://dsh.example',
      allowedSubjects: [{ issuer: 'https://id.example', subject: 'allowed' }],
    })
    const protocol = new FakeProtocol()
    protocol.claims = { iss: 'https://id.example', sub: 'allowed' }
    const admission = new OidcAdmission(
      bare,
      { resolve: vi.fn(async () => ({ value: 'rotating-secret', source: 'test' })) },
      { authenticatedUrl: (origin) => `${origin}?token=native-bootstrap` },
      protocol,
      { info: () => undefined, warn: () => undefined },
    )
    const started = await login(admission)
    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?code=code&state=${started.state}`, { cookie: started.cookie }),
      callback.value,
    )
    expect(callback.captured.status).toBe(200)
  })

  it('rejects transaction cookie and state from different login attempts', async () => {
    const { admission } = harness()
    const first = await login(admission)
    const second = await login(admission)
    const mismatched = response()
    await admission.callback(
      request('GET', `/auth/callback?code=code&state=${first.state}`, { cookie: second.cookie }),
      mismatched.value,
    )
    expect(mismatched.captured).toMatchObject({
      status: 400,
      body: 'invalid authentication response\n',
    })
  })

  it('requires same-origin CSRF POST logout and invalidates forward-auth immediately', async () => {
    const { admission } = harness()
    const started = await login(admission)
    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?state=${started.state}&code=c`, { cookie: started.cookie }),
      callback.value,
    )
    const session = cookieFrom(callback.captured.headers, SESSION_COOKIE)

    const confirmation = response()
    admission.logoutConfirmation(
      request('GET', '/auth/logout', { cookie: session }),
      confirmation.value,
    )
    expect(confirmation.captured.status).toBe(200)
    expect(confirmation.captured.headers?.['content-security-policy']).toContain(
      "default-src 'none'",
    )
    const csrf = confirmation.captured.body?.match(/name="csrf" value="([^"]+)"/u)?.[1]
    expect(csrf).toBeDefined()

    const crossOrigin = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie: session,
          origin: 'https://evil.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        `csrf=${csrf}`,
      ),
      crossOrigin.value,
    )
    expect(crossOrigin.captured.status).toBe(403)

    const wrongMediaType = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        { cookie: session, origin: 'https://dsh.example', 'content-type': 'application/json' },
        '{}',
      ),
      wrongMediaType.value,
    )
    expect(wrongMediaType.captured.status).toBe(415)

    const oversized = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie: session,
          origin: 'https://dsh.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        `csrf=${'x'.repeat(17_000)}`,
      ),
      oversized.value,
    )
    expect(oversized.captured.status).toBe(403)

    const wrongCsrf = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie: session,
          origin: 'https://dsh.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        'csrf=wrong',
      ),
      wrongCsrf.value,
    )
    expect(wrongCsrf.captured.status).toBe(403)

    const logout = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie: session,
          origin: 'https://dsh.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        `csrf=${csrf}`,
      ),
      logout.value,
    )
    expect(logout.captured).toMatchObject({
      status: 303,
      headers: { location: 'https://id.example/logout' },
    })
    expect(String(logout.captured.headers?.['set-cookie'])).toContain('Max-Age=0')

    const stale = response()
    admission.check(request('GET', '/auth/check', { cookie: session }), stale.value)
    expect(stale.captured.status).toBe(401)
  })
})

describe('logout body', () => {
  it('answers when the client goes away mid-body instead of waiting forever', async () => {
    const { admission } = harness()
    const started = await login(admission)
    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?state=${started.state}&code=c`, { cookie: started.cookie }),
      callback.value,
    )
    const session = cookieFrom(callback.captured.headers, SESSION_COOKIE)
    const body = new PassThrough()
    Object.assign(body, {
      method: 'POST',
      url: '/auth/logout',
      headers: {
        host: 'dsh.example',
        cookie: session,
        origin: 'https://dsh.example',
        'content-type': 'application/x-www-form-urlencoded',
      },
      socket: { remoteAddress: '127.0.0.1' },
    })
    const res = response()
    const answered = admission.logout(body as unknown as IncomingMessage, res.value)
    body.write('csrf=')
    body.destroy()
    const outcome = await Promise.race([
      answered.then(() => 'answered'),
      new Promise((resolve) => setTimeout(() => resolve('hung'), 500)),
    ])
    expect(outcome).toBe('answered')
    expect(res.captured.status).toBe(403)
    expect(admission.listSessions()).toHaveLength(1)
  })
})

describe('session metadata and audit trail', () => {
  async function signIn(
    admission: OidcAdmission,
    headers: Record<string, string> = {},
  ): Promise<string> {
    const started = await login(admission)
    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?state=${started.state}&code=c`, {
        cookie: started.cookie,
        ...headers,
      }),
      callback.value,
    )
    return cookieFrom(callback.captured.headers, SESSION_COOKIE)
  }

  it('records who signed in, from where, with which session', async () => {
    const { admission } = harness()
    const cookie = await signIn(admission, { 'user-agent': 'Firefox/140' })
    const [session] = admission.listSessions()
    expect(session).toMatchObject({
      kind: 'browser',
      ip: '192.0.2.10',
      userAgent: 'Firefox/140',
      principal: { subject: 'allowed' },
    })
    expect(session?.id).toMatch(/^[A-Za-z0-9_-]{22}$/u)
    expect(cookie).not.toContain(session!.id)
    expect(admission.audit.recent(10)).toEqual([
      expect.objectContaining({
        type: 'sign-in',
        person: { issuer: 'https://id.example/issuer', subject: 'allowed' },
        session: session!.id,
        ip: '192.0.2.10',
        userAgent: 'Firefox/140',
      }),
    ])
  })

  it('records a policy denial with the refused subject and no session', async () => {
    const { admission, protocol } = harness()
    protocol.claims = { iss: 'https://id.example/issuer', sub: 'stranger', email: 's@x.example' }
    const started = await login(admission)
    const callback = response()
    await admission.callback(
      request('GET', `/auth/callback?state=${started.state}&code=c`, { cookie: started.cookie }),
      callback.value,
    )
    expect(callback.captured.status).toBe(403)
    expect(admission.listSessions()).toEqual([])
    expect(admission.audit.recent(1)[0]).toMatchObject({
      type: 'sign-in-denied',
      person: { subject: 'stranger', name: 's@x.example' },
      ip: '192.0.2.10',
    })
  })

  it('records sign-out and ends the session in the list', async () => {
    const { admission } = harness()
    const cookie = await signIn(admission)
    const { csrf, id } = admission.currentSession(request('GET', '/', { cookie }))!
    const res = response()
    await admission.logout(
      request(
        'POST',
        '/auth/logout',
        {
          cookie,
          origin: 'https://dsh.example',
          'content-type': 'application/x-www-form-urlencoded',
        },
        `csrf=${csrf}`,
      ),
      res.value,
    )
    expect(res.captured.status).toBe(303)
    expect(admission.listSessions()).toEqual([])
    expect(admission.audit.recent(1)[0]).toMatchObject({ type: 'sign-out', session: id })
  })

  it('revokes another session by id, names who did it, and the revoked cookie stops working', async () => {
    const { admission } = harness()
    const first = await signIn(admission)
    const second = await signIn(admission)
    const actor = admission.currentSession(request('GET', '/', { cookie: first }))!
    const target = admission.currentSession(request('GET', '/', { cookie: second }))!
    const ended: string[] = []
    admission.sessions.onEnd((session, reason) => ended.push(`${session.id}:${reason}`))

    expect(await admission.revokeSession('A'.repeat(22), actor)).toBeUndefined()
    const revoked = await admission.revokeSession(target.id, actor)
    expect(revoked?.id).toBe(target.id)
    expect(ended).toEqual([`${target.id}:revoked`])
    expect(admission.listSessions().map(({ id }) => id)).toEqual([actor.id])
    expect(admission.principalOf(request('GET', '/', { cookie: second }))).toBeUndefined()
    expect(admission.audit.recent(1)[0]).toMatchObject({
      type: 'session-revoked',
      session: target.id,
      person: { subject: 'allowed' },
      by: { subject: 'allowed' },
    })
    const check = response()
    admission.check(request('GET', '/auth/check', { cookie: second }), check.value)
    expect(check.captured.status).toBe(401)
  })
})
