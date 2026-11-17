import {
  createServer as createHttpServer,
  request as httpRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  type Server,
  type ServerResponse,
} from 'node:http'
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https'
import { isIP } from 'node:net'
import type { Duplex } from 'node:stream'
import type { GatewayConfig } from './config.js'
import { normalizedTarget, targetPath, type PublicPaths } from './public-paths.js'
import type { SessionEndReason, SessionSummary, SessionView } from './state.js'

/**
 * Gateway mode: the plugin's own listener is the only way into DSH.
 *
 * DSH's web server moves to loopback and this listener takes the public
 * address. Every request and WebSocket upgrade passes one decision: the
 * plugin's sign-in routes are answered here, GET and HEAD of the configured
 * public files (manifest, app icons) go through without DSH's cookie, and
 * everything else, every upgrade included, needs a live session of this
 * plugin or gets the sign-in redirect (navigations) or 401. Signed-in traffic
 * is streamed to DSH's loopback origin with DSH's own cookie added, which the
 * gateway mints itself, so browsers never hold DSH's 30-day credential or see
 * its launch token. Sockets and long responses are tracked per session and
 * closed when the session ends, so signing out or revoking cuts live
 * WebSockets and event streams too.
 *
 * Only public DSH APIs are used: `webServer.getOrigin()` to find the loopback
 * listener and `connection.authenticatedUrl()` for the cookie exchange.
 */

/** Hop-by-hop headers (RFC 9110 7.6.1) plus the old proxy ones; never forwarded. */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

const NATIVE_COOKIE_PREFIX = 'dsh-auth-'
const CLIENT_IP_HEADER = 'x-dsh-oidc-client-ip'

const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
} as const

/** How often the gateway renews DSH's cookie; DSH's own minimum lifetime is one day. */
export const NATIVE_COOKIE_REFRESH_MILLISECONDS = 6 * 60 * 60 * 1000
/** Retry after a failed cookie exchange. */
export const NATIVE_COOKIE_RETRY_MILLISECONDS = 30_000
/** How often expired sessions are swept, which closes their connections. */
export const SWEEP_MILLISECONDS = 60_000

export interface GatewayLogger {
  info(message: string): void
  warn(message: string): void
}

/** What the gateway needs from the rest of the plugin. */
export interface GatewayHost {
  /** Sign-in routes answered in process, by exact path. */
  readonly routes: ReadonlyMap<string, (req: IncomingMessage, res: ServerResponse) => unknown>
  /** The live session the request carries, if any. */
  session(req: IncomingMessage): SessionView | undefined
  /** Where a signed-out navigation goes. */
  readonly signInPath: string
  /** Whether the request is a top-level browser navigation. */
  wantsNavigation(req: IncomingMessage): boolean
  /** The client's address for this request (socket peer or trusted proxy header). */
  clientIp(req: IncomingMessage): string | undefined
  /** Remember the address for the in-process routes. */
  markClientIp(req: IncomingMessage, ip: string): void
  onSessionEnd(listener: (session: SessionSummary, reason: SessionEndReason) => void): () => void
  sweep(): void
  /** DSH's loopback origin, such as `http://127.0.0.1:3081`. */
  upstream(): URL
  /** DSH's launch-token URL for `base`. */
  authenticatedUrl(base: string): string
  /** The public `Host` value DSH's fence and cookie are bound to. */
  readonly publicHost: string
  /** Static files that load without a session. */
  readonly publicPaths: PublicPaths
}

export interface GatewayTls {
  readonly cert: Buffer | string
  readonly key: Buffer | string
}

/** Whether a bind address is loopback only. */
export function isLoopback(host: string | undefined): boolean {
  if (host === undefined) return false
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host
  if (bare === 'localhost' || bare === '::1') return true
  return isIP(bare) === 4 && bare.startsWith('127.')
}

function connectionTokens(headers: IncomingHttpHeaders): Set<string> {
  const raw = headers.connection
  const value = Array.isArray(raw) ? raw.join(',') : (raw ?? '')
  return new Set(
    value
      .split(',')
      .map((token) => token.trim().toLowerCase())
      .filter((token) => token !== ''),
  )
}

/** Drop every `dsh-auth-*` cookie a client sent, then add the gateway's own. */
export function rewriteCookie(raw: string | undefined, native: string | undefined): string {
  const kept = (raw ?? '')
    .split(';')
    .map((segment) => segment.trim())
    .filter((segment) => segment !== '' && !segment.startsWith(NATIVE_COOKIE_PREFIX))
  if (native !== undefined) kept.push(native)
  return kept.join('; ')
}

/** Request headers for DSH: hop-by-hop gone, client native cookies replaced, client IP set. */
export function upstreamHeaders(
  headers: IncomingHttpHeaders,
  native: string | undefined,
  clientIp: string | undefined,
  upgrade = false,
): OutgoingHttpHeaders {
  const drop = connectionTokens(headers)
  const out: OutgoingHttpHeaders = {}
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || HOP_BY_HOP.has(name) || drop.has(name)) continue
    if (name === 'cookie' || name === CLIENT_IP_HEADER) continue
    out[name] = value
  }
  const cookie = rewriteCookie(
    Array.isArray(headers.cookie) ? headers.cookie.join('; ') : headers.cookie,
    native,
  )
  if (cookie !== '') out.cookie = cookie
  if (clientIp !== undefined) out[CLIENT_IP_HEADER] = clientIp
  if (upgrade && headers.upgrade !== undefined) {
    out.connection = 'Upgrade'
    out.upgrade = headers.upgrade
  }
  return out
}

/** Response headers for the client: hop-by-hop gone, DSH's own cookies never leave. */
export function downstreamHeaders(headers: IncomingHttpHeaders): OutgoingHttpHeaders {
  const drop = connectionTokens(headers)
  const out: OutgoingHttpHeaders = {}
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined || HOP_BY_HOP.has(name) || drop.has(name)) continue
    if (name === 'set-cookie') {
      const kept = (Array.isArray(value) ? value : [value]).filter(
        (cookie) => !cookie.trimStart().startsWith(NATIVE_COOKIE_PREFIX),
      )
      if (kept.length > 0) out[name] = kept
      continue
    }
    out[name] = value
  }
  return out
}

function rawResponse(socket: Duplex, status: number, reason: string): void {
  if (socket.writable)
    socket.end(
      `HTTP/1.1 ${String(status)} ${reason}\r\nconnection: close\r\ncache-control: no-store\r\ncontent-length: 0\r\n\r\n`,
    )
  socket.destroy()
}

function plain(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'text/plain; charset=utf-8' })
  res.end(res.req.method === 'HEAD' ? undefined : body)
}

/** Parse one `Set-Cookie` value into `name=value`. */
function cookiePair(setCookie: string): string | undefined {
  const pair = setCookie.split(';', 1)[0]?.trim()
  return pair !== undefined && pair.includes('=') ? pair : undefined
}

export class Gateway {
  private server: Server | undefined
  private native: string | undefined
  private refreshTimer: NodeJS.Timeout | undefined
  private sweepTimer: NodeJS.Timeout | undefined
  private readonly live = new Map<string, Set<Duplex>>()
  private disposeEnd: (() => void) | undefined

  constructor(
    private readonly config: GatewayConfig,
    private readonly host: GatewayHost,
    private readonly logger: GatewayLogger,
    private readonly tls?: GatewayTls,
  ) {}

  /** Mint DSH's cookie, then open the public listener. */
  async start(): Promise<void> {
    await this.refreshNative()
    this.disposeEnd = this.host.onSessionEnd((session) => {
      this.close(session.id)
    })
    this.sweepTimer = setInterval(() => {
      this.host.sweep()
    }, SWEEP_MILLISECONDS)
    this.sweepTimer.unref()
    const handler = (req: IncomingMessage, res: ServerResponse) => {
      this.request(req, res)
    }
    const server =
      this.tls === undefined
        ? createHttpServer(handler)
        : createHttpsServer({ cert: this.tls.cert, key: this.tls.key }, handler)
    server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
      this.upgrade(req, socket, head)
    })
    server.on('clientError', (_error, socket: Duplex) => {
      rawResponse(socket, 400, 'Bad Request')
    })
    this.server = server
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(this.config.port, this.config.host, () => {
        server.off('error', reject)
        resolve()
      })
    })
    if (!isLoopback(this.config.host))
      this.logger.warn(
        `dsh-oidc: gateway listens on ${this.config.host}; it is the only sign-in check in front of DSH, so keep everything else off that address`,
      )
    this.logger.info(
      `dsh-oidc: gateway listening on ${this.config.host}:${String(this.config.port)}${this.tls === undefined ? '' : ' (TLS)'}`,
    )
  }

  /** Close the listener and every connection through it. */
  async stop(): Promise<void> {
    clearTimeout(this.refreshTimer)
    clearInterval(this.sweepTimer)
    this.disposeEnd?.()
    for (const sockets of this.live.values()) for (const socket of sockets) socket.destroy()
    this.live.clear()
    const server = this.server
    this.server = undefined
    if (server === undefined) return
    server.closeAllConnections()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }

  /** The bound port, once listening. */
  get port(): number | undefined {
    const address = this.server?.address()
    return typeof address === 'object' && address !== null ? address.port : undefined
  }

  /** Sockets currently tracked for a session; for tests and diagnostics. */
  liveCount(sessionId: string): number {
    return this.live.get(sessionId)?.size ?? 0
  }

  /** Exchange DSH's launch token for its browser cookie, on the loopback listener. */
  async refreshNative(): Promise<void> {
    clearTimeout(this.refreshTimer)
    try {
      this.native = await this.exchange()
      this.refreshTimer = setTimeout(
        () => void this.refreshNative(),
        NATIVE_COOKIE_REFRESH_MILLISECONDS,
      )
    } catch (error) {
      if (this.native === undefined && this.server === undefined) throw error
      this.logger.warn('dsh-oidc: gateway could not renew the DSH cookie; retrying')
      this.refreshTimer = setTimeout(
        () => void this.refreshNative(),
        NATIVE_COOKIE_RETRY_MILLISECONDS,
      )
    }
    this.refreshTimer.unref()
  }

  private exchange(): Promise<string> {
    const upstream = this.host.upstream()
    const target = new URL(this.host.authenticatedUrl(upstream.href))
    return new Promise((resolve, reject) => {
      const send = upstream.protocol === 'https:' ? httpsRequest : httpRequest
      const request = send(
        {
          host: upstream.hostname,
          port: upstream.port,
          method: 'GET',
          path: `${target.pathname}${target.search}`,
          headers: { host: this.host.publicHost },
          rejectUnauthorized: false,
          signal: AbortSignal.timeout(10_000),
        },
        (response) => {
          response.resume()
          const raw = response.headers['set-cookie'] ?? []
          const native = raw
            .map(cookiePair)
            .find((pair) => pair?.startsWith(NATIVE_COOKIE_PREFIX) === true)
          if (response.statusCode === 303 && native !== undefined) resolve(native)
          else
            reject(
              new Error(
                `dsh-oidc: DSH did not mint its browser cookie for the gateway (HTTP ${String(response.statusCode)})`,
              ),
            )
        },
      )
      request.once('error', reject)
      request.end()
    })
  }

  private track(sessionId: string, socket: Duplex): () => void {
    let sockets = this.live.get(sessionId)
    if (sockets === undefined) {
      sockets = new Set()
      this.live.set(sessionId, sockets)
    }
    sockets.add(socket)
    const owned = sockets
    return () => {
      owned.delete(socket)
      if (owned.size === 0 && this.live.get(sessionId) === owned) this.live.delete(sessionId)
    }
  }

  private close(sessionId: string): void {
    const sockets = this.live.get(sessionId)
    if (sockets === undefined) return
    this.live.delete(sessionId)
    for (const socket of sockets) socket.destroy()
  }

  private request(req: IncomingMessage, res: ServerResponse): void {
    const target = normalizedTarget(req.url)
    if (target === undefined) return plain(res, 400, 'bad request\n')
    const path = targetPath(target)
    // Every forwarded request carries the client address, which is also what
    // tells DSH's side it came through the gate rather than from this host.
    const ip = this.host.clientIp(req)
    if (ip === undefined) return plain(res, 400, 'bad request\n')
    this.host.markClientIp(req, ip)
    const route = this.host.routes.get(path)
    if (route !== undefined) {
      void Promise.resolve(route(req, res)).catch(() => {
        if (!res.headersSent) plain(res, 500, 'internal error\n')
        else res.destroy()
      })
      return
    }
    if (path.startsWith('/auth/') || path === '/connect') return plain(res, 404, 'not found\n')
    let session: SessionView | undefined
    if (!this.host.publicPaths.allows(req.method, path)) {
      session = this.host.session(req)
      if (session === undefined) {
        if ((req.method === 'GET' || req.method === 'HEAD') && this.host.wantsNavigation(req)) {
          res.writeHead(303, { ...SECURITY_HEADERS, location: this.host.signInPath })
          res.end()
          return
        }
        return plain(res, 401, 'unauthorized\n')
      }
    }
    this.forward(req, res, target, ip, session)
  }

  private forward(
    req: IncomingMessage,
    res: ServerResponse,
    target: string,
    ip: string,
    session: SessionView | undefined,
  ): void {
    const upstream = this.host.upstream()
    const send = upstream.protocol === 'https:' ? httpsRequest : httpRequest
    const untrack = session === undefined ? undefined : this.track(session.id, req.socket)
    const outgoing = send({
      host: upstream.hostname,
      port: upstream.port,
      method: req.method,
      path: target,
      // A public file is fetched as an anonymous browser would, without DSH's cookie.
      headers: upstreamHeaders(req.headers, session === undefined ? undefined : this.native, ip),
      rejectUnauthorized: false,
    })
    const finish = () => {
      untrack?.()
    }
    res.once('close', () => {
      finish()
      if (!res.writableFinished) outgoing.destroy()
    })
    outgoing.once('response', (response) => {
      res.writeHead(response.statusCode ?? 502, downstreamHeaders(response.headers))
      response.pipe(res)
      response.once('error', () => res.destroy())
    })
    outgoing.once('error', () => {
      if (!res.headersSent) plain(res, 502, 'bad gateway\n')
      else res.destroy()
    })
    req.pipe(outgoing)
  }

  private upgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    socket.on('error', () => socket.destroy())
    const target = normalizedTarget(req.url)
    if (target === undefined) return rawResponse(socket, 400, 'Bad Request')
    const path = targetPath(target)
    if (this.host.routes.has(path) || path.startsWith('/auth/') || path === '/connect')
      return rawResponse(socket, 404, 'Not Found')
    const ip = this.host.clientIp(req)
    if (ip === undefined) return rawResponse(socket, 400, 'Bad Request')
    // Public files are never a reason to open a socket: every upgrade needs a session.
    const session = this.host.session(req)
    if (session === undefined) return rawResponse(socket, 401, 'Unauthorized')
    const untrack = this.track(session.id, socket)
    socket.once('close', untrack)
    const upstream = this.host.upstream()
    const send = upstream.protocol === 'https:' ? httpsRequest : httpRequest
    const outgoing = send({
      host: upstream.hostname,
      port: upstream.port,
      method: req.method,
      path: target,
      headers: upstreamHeaders(req.headers, this.native, ip, true),
      rejectUnauthorized: false,
    })
    outgoing.once('upgrade', (response, upstreamSocket, upstreamHead) => {
      if (socket.destroyed) {
        upstreamSocket.destroy()
        return
      }
      const lines = [`HTTP/1.1 101 ${response.statusMessage ?? 'Switching Protocols'}`]
      const headers = downstreamHeaders(response.headers)
      headers.connection = 'Upgrade'
      if (response.headers.upgrade !== undefined) headers.upgrade = response.headers.upgrade
      for (const [name, value] of Object.entries(headers))
        for (const item of Array.isArray(value) ? value : [value])
          if (item !== undefined) lines.push(`${name}: ${String(item)}`)
      socket.write(`${lines.join('\r\n')}\r\n\r\n`)
      if (upstreamHead.length > 0) socket.write(upstreamHead)
      if (head.length > 0) upstreamSocket.write(head)
      upstreamSocket.on('error', () => socket.destroy())
      socket.once('close', () => upstreamSocket.destroy())
      upstreamSocket.once('close', () => socket.destroy())
      upstreamSocket.pipe(socket).pipe(upstreamSocket)
    })
    outgoing.once('response', (response) => {
      // DSH refused the upgrade: pass its status on and close.
      response.resume()
      rawResponse(socket, response.statusCode ?? 502, response.statusMessage ?? 'Refused')
    })
    outgoing.once('error', () => rawResponse(socket, 502, 'Bad Gateway'))
    socket.once('close', () => outgoing.destroy())
    outgoing.end()
  }
}
