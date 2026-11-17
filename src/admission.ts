import { randomBytes } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { isIP } from 'node:net'
import type { CredentialRef, ResolvedCredential } from '@deepseek-ai/dsh-credentials'
import { AuditLog, type AuditPerson } from './audit.js'
import type { ResolvedConfig, TrustedProxies } from './config.js'
import type { OidcProtocol } from './oidc.js'
import { normalizedTarget, targetPath } from './public-paths.js'
import { authorizeClaims, type Principal } from './policy.js'
import {
  AuthorizationTransactions,
  BrowserSessions,
  FixedWindowRateLimiter,
  SESSION_COOKIE,
  TRANSACTION_COOKIE,
  type SessionPersistence,
  type SessionSummary,
  type SessionView,
  expiredCookie,
  readCookie,
  secureCookie,
} from './state.js'

const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
} as const

export const CLIENT_IP_HEADER = 'x-dsh-oidc-client-ip'

export interface AdmissionLogger {
  info(message: string): void
  warn(message: string): void
}

export interface CredentialResolver {
  resolve(reference: CredentialRef): Promise<ResolvedCredential | undefined>
}

export interface NativeConnectionLauncher {
  authenticatedUrl(baseUrl: string): string
}

function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return typeof value === 'string' ? value : undefined
}

function normalizedIp(value: string): string | undefined {
  if (value.length === 0 || value.trim() !== value || value.includes(',')) return undefined
  if (value.startsWith('::ffff:')) {
    const mapped = value.slice('::ffff:'.length)
    if (isIP(mapped) === 4) return `::ffff:${mapped}`
  }
  const version = isIP(value)
  if (version === 4) return value
  if (version === 6) {
    const hostname = new URL(`http://[${value}]/`).hostname
    return hostname.slice(1, -1)
  }
  return undefined
}

/**
 * Client addresses the gateway already established for a request it handles
 * in process, so admission doesn't read the header from the gateway's peer.
 */
const gatewayClientIps = new WeakMap<IncomingMessage, string>()

export function setGatewayClientIp(req: IncomingMessage, ip: string): void {
  gatewayClientIps.set(req, ip)
}

/**
 * The client's address: the proxy-set header when the socket peer is a
 * trusted proxy, else (only when `peerFallback`) the socket peer itself.
 */
export function clientAddress(
  req: IncomingMessage,
  proxies: TrustedProxies,
  peerFallback: boolean,
): string | undefined {
  const forwarded = trustedClientIp(req, proxies)
  if (forwarded !== undefined || !peerFallback) return forwarded
  const peer = req.socket.remoteAddress
  return peer === undefined ? undefined : normalizedIp(peer)
}

/** The proxy-set client address, believed only when the socket peer is a configured trusted proxy. */
function trustedClientIp(req: IncomingMessage, proxies: TrustedProxies): string | undefined {
  const established = gatewayClientIps.get(req)
  if (established !== undefined) return established
  const peer = req.socket.remoteAddress
  if (peer === undefined || !proxies.has(peer)) return undefined
  const raw = req.headers[CLIENT_IP_HEADER]
  if (typeof raw !== 'string') return undefined
  return normalizedIp(raw)
}

function methodNotAllowed(res: ServerResponse, allow: string): void {
  res.writeHead(405, { ...SECURITY_HEADERS, allow })
  res.end()
}

function plain(res: ServerResponse, status: number, body: string, head = false): void {
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'text/plain; charset=utf-8' })
  res.end(head ? undefined : body)
}

function redirect(res: ServerResponse, location: string, cookies: readonly string[] = []): void {
  res.writeHead(303, {
    ...SECURITY_HEADERS,
    location,
    ...(cookies.length === 0 ? {} : { 'set-cookie': [...cookies] }),
  })
  res.end()
}

function htmlAttribute(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
}

function bootstrapPage(res: ServerResponse, location: string, cookies: readonly string[]): void {
  const target = htmlAttribute(location)
  res.writeHead(200, {
    ...SECURITY_HEADERS,
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    'set-cookie': [...cookies],
  })
  res.end(
    `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=${target}"><title>Signing in</title><a href="${target}">Continue</a>`,
  )
}

function formBody(req: IncomingMessage, maximum = 16_384): Promise<URLSearchParams | undefined> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    let exceeded = false
    req.on('data', (chunk: Buffer) => {
      if (exceeded) return
      size += chunk.byteLength
      if (size > maximum) {
        exceeded = true
        chunks.length = 0
        resolve(undefined)
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      if (!exceeded) resolve(new URLSearchParams(Buffer.concat(chunks).toString('utf8')))
    })
    req.on('error', reject)
  })
}

const SIGNIN_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>Sign in · DSH</title><style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#111;color:#eee}main{text-align:center;padding:2rem}a{display:inline-block;margin-top:1rem;padding:.6rem 1.4rem;background:#2563eb;color:#fff;border-radius:.5rem;text-decoration:none;font-weight:600}</style></head><body><main><h1>DSH</h1><p>Authentication required.</p><a href="/auth/login?nav=1" rel="nofollow">Sign in</a></main></body></html>`

export function wantsNavigation(req: IncomingMessage): boolean {
  const fetchMode = header(req, 'sec-fetch-mode')
  if (fetchMode !== undefined) return fetchMode === 'navigate'
  const accept = header(req, 'accept') ?? ''
  return (
    !accept.includes('*/*') &&
    (accept.includes('text/html') || accept.includes('application/xhtml+xml'))
  )
}

/** The person a principal names, for the audit log. */
export function auditPerson(principal: Principal): AuditPerson {
  const name = principal.username ?? principal.displayName ?? principal.email
  return {
    issuer: principal.issuer,
    subject: principal.subject,
    ...(name === undefined ? {} : { name }),
  }
}

function claimText(claims: Readonly<Record<string, unknown>>, name: string): string | undefined {
  const value = claims[name]
  return typeof value === 'string' && value !== '' && value.length <= 4096 ? value : undefined
}

export class OidcAdmission {
  private readonly transactions: AuthorizationTransactions
  readonly sessions: BrowserSessions
  readonly audit: AuditLog
  private readonly limiter: FixedWindowRateLimiter

  constructor(
    private readonly config: ResolvedConfig,
    private readonly credentials: CredentialResolver,
    private readonly connection: NativeConnectionLauncher,
    private readonly protocol: OidcProtocol,
    private readonly logger: AdmissionLogger,
    persistence?: SessionPersistence,
    audit?: AuditLog,
  ) {
    this.transactions = new AuthorizationTransactions(
      config.transactionMaxAgeSeconds * 1000,
      config.maxTransactions,
    )
    this.sessions = new BrowserSessions(
      config.sessionMaxAgeSeconds * 1000,
      config.sessionIdleTimeoutSeconds * 1000,
      config.maxSessions,
      persistence,
    )
    this.limiter = new FixedWindowRateLimiter(config.loginRateLimitPerMinute)
    this.audit =
      audit ??
      new AuditLog({
        retentionMilliseconds: config.auditRetentionDays * 86_400_000,
        maxEvents: config.maxAuditEvents,
        onError: () => logger.warn('dsh-oidc: audit log write failed'),
        emit: () => undefined,
      })
  }

  /** Load persisted sessions; a no-op without persistence. */
  restoreSessions(now = Date.now()): Promise<number> {
    return this.sessions.restore(now)
  }

  private correlation(): string {
    return randomBytes(8).toString('hex')
  }

  private trustedRequest(req: IncomingMessage): boolean {
    return header(req, 'host') === this.config.publicOrigin.host
  }

  private sessionValue(req: IncomingMessage): string | undefined {
    return readCookie(header(req, 'cookie'), SESSION_COOKIE)
  }

  private async secret(): Promise<string | undefined> {
    const reference: CredentialRef | undefined = this.config.clientSecretRef
    if (reference === undefined) return undefined
    const resolved = await this.credentials.resolve(reference)
    if (resolved === undefined) throw new Error('configured OIDC client credential is unavailable')
    return resolved.value
  }

  async login(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(res, 'GET, HEAD')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n')
    if (header(req, 'sec-fetch-site') === 'cross-site') return plain(res, 403, 'forbidden\n')
    const clientIp = trustedClientIp(req, this.config.trustedProxies)
    if (clientIp === undefined) return plain(res, 403, 'forbidden\n')
    if (req.method === 'HEAD') return plain(res, 204, '', true)
    if (!this.limiter.admit(clientIp)) return plain(res, 429, 'too many requests\n')
    const correlation = this.correlation()
    try {
      const started = await this.protocol.start(await this.secret())
      const transaction = this.transactions.create(started.verifier, started.nonce)
      if (transaction === undefined) return plain(res, 503, 'authentication unavailable\n')
      started.url.searchParams.set('state', transaction.state)
      redirect(res, started.url.href, [
        secureCookie(TRANSACTION_COOKIE, transaction.id, this.config.transactionMaxAgeSeconds),
      ])
      this.logger.info(`dsh-oidc login started correlation=${correlation}`)
    } catch {
      this.logger.warn(`dsh-oidc login failed correlation=${correlation}`)
      plain(res, 503, 'authentication unavailable\n')
    }
  }

  async callback(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'GET') return methodNotAllowed(res, 'GET')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n')
    const correlation = this.correlation()
    const incoming = new URL(req.url ?? '/auth/callback', this.config.publicOrigin)
    const transaction = this.transactions.consume(
      readCookie(header(req, 'cookie'), TRANSACTION_COOKIE),
      incoming.searchParams.getAll('state').length === 1
        ? (incoming.searchParams.get('state') ?? undefined)
        : undefined,
    )
    if (transaction === undefined) {
      this.logger.warn(`dsh-oidc callback rejected correlation=${correlation}`)
      return plain(res, 400, 'invalid authentication response\n')
    }
    try {
      const currentUrl = new URL(this.config.redirectUri)
      currentUrl.search = incoming.search
      const claims = await this.protocol.callback(await this.secret(), {
        verifier: transaction.verifier,
        nonce: transaction.nonce,
        state: transaction.state,
        currentUrl,
      })
      const principal = authorizeClaims(claims, this.config.issuerId, this.config.policy)
      const ip = trustedClientIp(req, this.config.trustedProxies)
      const userAgent = header(req, 'user-agent')
      const where = {
        ...(ip === undefined ? {} : { ip }),
        ...(userAgent === undefined ? {} : { userAgent }),
      }
      if (principal === undefined) {
        this.logger.warn(`dsh-oidc policy denied correlation=${correlation}`)
        const subject = claimText(claims, 'sub')
        const name = claimText(claims, 'preferred_username') ?? claimText(claims, 'email')
        this.audit.record({
          type: 'sign-in-denied',
          ...(subject === undefined
            ? {}
            : {
                person: {
                  issuer: claimText(claims, 'iss') ?? this.config.issuerId,
                  subject,
                  ...(name === undefined ? {} : { name }),
                },
              }),
          ...where,
        })
        return plain(res, 403, 'access denied\n')
      }
      const session = this.sessions.create(principal, { kind: 'browser', ...where })
      if (session === undefined) return plain(res, 503, 'authentication unavailable\n')
      this.audit.record({
        type: 'sign-in',
        person: auditPerson(principal),
        session: session.id,
        ...where,
      })
      // The callback arrives on a navigation started by the provider's site, so
      // a plain redirect keeps the whole chain cross-site and the browser never
      // sends DSH's SameSite=Strict native cookie after the token exchange.
      // A same-origin page that starts a fresh navigation makes it same-site.
      // In gateway mode the browser never holds DSH's cookie: the gateway adds
      // its own on the way in, so the page continues to the app itself.
      const next =
        this.config.mode === 'gateway'
          ? this.config.publicOrigin.href
          : this.connection.authenticatedUrl(this.config.publicOrigin.href)
      bootstrapPage(res, next, [
        secureCookie(SESSION_COOKIE, session.value, this.config.sessionMaxAgeSeconds),
        expiredCookie(TRANSACTION_COOKIE),
      ])
      this.logger.info(`dsh-oidc login admitted correlation=${correlation}`)
    } catch {
      this.logger.warn(`dsh-oidc callback failed correlation=${correlation}`)
      plain(res, 400, 'invalid authentication response\n')
    }
  }

  signin(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(res, 'GET, HEAD')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n')
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy':
        "default-src 'none'; style 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
    })
    res.end(req.method === 'HEAD' ? undefined : SIGNIN_HTML)
  }

  check(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET' && req.method !== 'HEAD') return methodNotAllowed(res, 'GET, HEAD')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n', req.method === 'HEAD')
    if (this.publicRequest(req)) return plain(res, 204, '', req.method === 'HEAD')
    const session = this.sessions.read(this.sessionValue(req))
    if (session !== undefined) return plain(res, 204, '', req.method === 'HEAD')
    // Browser navigations go to the bundled sign-in page, or straight to the
    // provider with `directLogin`; every other client (fetch/XHR/API/WebSocket
    // subrequests) keeps the plain 401 contract.
    if (req.method === 'GET' && wantsNavigation(req))
      return redirect(res, this.config.directLogin ? '/auth/login?nav=1' : '/auth/signin')
    plain(res, 401, 'unauthorized\n', req.method === 'HEAD')
  }

  /**
   * Whether the request the proxy is asking about is a GET or HEAD of a
   * configured public file. The original method and URI come from the
   * proxy's `X-Forwarded-Method` and `X-Forwarded-Uri`, which Caddy and
   * Traefik set themselves on a forward-auth subrequest; they are believed
   * only from a trusted proxy, so a client can't name a public file to get
   * another path through.
   */
  private publicRequest(req: IncomingMessage): boolean {
    const peer = req.socket.remoteAddress
    if (peer === undefined || !this.config.trustedProxies.has(peer)) return false
    const target = normalizedTarget(header(req, 'x-forwarded-uri'))
    return (
      target !== undefined &&
      this.config.publicPaths.allows(header(req, 'x-forwarded-method'), targetPath(target))
    )
  }

  /**
   * The verified principal of the request's live OIDC session, read from this
   * plugin's own HttpOnly session cookie only; undefined without one.
   */
  principalOf(req: IncomingMessage): Principal | undefined {
    return this.currentSession(req)?.principal
  }

  /** The live session the request's cookie names, refreshing its last use. */
  currentSession(req: IncomingMessage): SessionView | undefined {
    return this.sessions.read(this.sessionValue(req))
  }

  /** The live session a raw Cookie header names. */
  sessionFromCookie(cookie: string | null | undefined): SessionView | undefined {
    return this.sessions.read(readCookie(cookie ?? undefined, SESSION_COOKIE))
  }

  /** Every live session, most recently used first. */
  listSessions(): SessionSummary[] {
    return this.sessions.list()
  }

  /**
   * End the session with public id `id` on behalf of `actor`, durably.
   * @returns the revoked session, or undefined when none is live with that id.
   */
  async revokeSession(
    id: string,
    actor: { readonly principal: Principal },
  ): Promise<SessionSummary | undefined> {
    const revoked = await this.sessions.revoke(id)
    if (revoked === undefined) return undefined
    this.audit.record({
      type: 'session-revoked',
      person: auditPerson(revoked.principal),
      by: auditPerson(actor.principal),
      session: revoked.id,
    })
    return revoked
  }

  /**
   * The signed-in profile the sidebar account button shows, plus the session's
   * logout CSRF value. Served behind the proxy's forward_auth like every
   * application path, and the session is checked here again, so the route
   * answers nothing without a live OIDC session. It carries display claims
   * only; tokens never leave the Host.
   */
  session(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') return methodNotAllowed(res, 'GET')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n')
    const site = header(req, 'sec-fetch-site')
    if (site !== undefined && site !== 'same-origin') return plain(res, 403, 'forbidden\n')
    const session = this.sessions.read(this.sessionValue(req))
    if (session === undefined) return plain(res, 401, 'unauthorized\n')
    const { principal } = session
    const body: Record<string, string> = { csrf: session.csrf }
    if (principal.displayName !== undefined) body.name = principal.displayName
    if (principal.username !== undefined) body.username = principal.username
    if (principal.email !== undefined) body.email = principal.email
    if (principal.picture !== undefined) body.picture = principal.picture
    res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify(body))
  }

  logoutConfirmation(req: IncomingMessage, res: ServerResponse): void {
    if (req.method !== 'GET') return methodNotAllowed(res, 'GET, POST')
    if (!this.trustedRequest(req)) return plain(res, 403, 'forbidden\n')
    if (header(req, 'sec-fetch-site') === 'cross-site') return plain(res, 403, 'forbidden\n')
    const session = this.sessions.read(this.sessionValue(req))
    if (session === undefined) return plain(res, 401, 'unauthorized\n')
    const html = `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Sign out</title><form method="post" action="/auth/logout"><input type="hidden" name="csrf" value="${session.csrf}"><button type="submit">Sign out</button></form>`
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy':
        "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    })
    res.end(html)
  }

  async logout(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') return methodNotAllowed(res, 'GET, POST')
    if (!this.trustedRequest(req) || header(req, 'origin') !== this.config.publicOrigin.origin)
      return plain(res, 403, 'forbidden\n')
    if (
      header(req, 'content-type')?.split(';', 1)[0]?.trim().toLowerCase() !==
      'application/x-www-form-urlencoded'
    )
      return plain(res, 415, 'unsupported media type\n')
    const value = this.sessionValue(req)
    const session = this.sessions.read(value)
    const body = await formBody(req)
    if (session === undefined || body?.get('csrf') !== session.csrf)
      return plain(res, 403, 'forbidden\n')
    await this.sessions.delete(value)
    this.audit.record({
      type: 'sign-out',
      person: auditPerson(session.principal),
      session: session.id,
      ...(session.ip === undefined ? {} : { ip: session.ip }),
    })
    let destination = this.config.publicOrigin.href
    try {
      destination = (await this.protocol.logoutUrl(await this.secret()))?.href ?? destination
    } catch {
      // Local logout remains complete when optional provider logout is unavailable.
    }
    redirect(res, destination, [expiredCookie(SESSION_COOKIE)])
    this.logger.info(`dsh-oidc logout completed correlation=${this.correlation()}`)
  }
}
