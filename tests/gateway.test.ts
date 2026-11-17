import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import { connect, type Socket } from 'node:net'
import { once } from 'node:events'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  Gateway,
  downstreamHeaders,
  isLoopback,
  isPublicPath,
  normalizedTarget,
  rewriteCookie,
  upstreamHeaders,
  type GatewayHost,
} from '../src/gateway.js'
import type { SessionEndReason, SessionSummary, SessionView } from '../src/state.js'

const PUBLIC_HOST = 'dsh.example'
const TOKEN = 'launch-token'
const NATIVE = 'dsh-auth-abc=minted'

interface Upstream {
  server: Server
  origin: string
  seen: IncomingMessage[]
  bodies: string[]
  streams: ServerResponse[]
  mintStatus: number
}

async function startUpstream(): Promise<Upstream> {
  const state: Upstream = {
    server: createServer(),
    origin: '',
    seen: [],
    bodies: [],
    streams: [],
    mintStatus: 303,
  }
  state.server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://upstream')
    if (url.searchParams.get('token') === TOKEN) {
      res.writeHead(state.mintStatus, {
        location: './',
        'set-cookie': `${NATIVE}; Path=/; HttpOnly; SameSite=Strict`,
      })
      res.end()
      return
    }
    state.seen.push(req)
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      state.bodies.push(Buffer.concat(chunks).toString('utf8'))
      if (url.pathname === '/events') {
        res.writeHead(200, { 'content-type': 'text/event-stream' })
        res.write('data: hello\n\n')
        state.streams.push(res)
        return
      }
      res.writeHead(200, {
        'content-type': 'text/plain',
        connection: 'keep-alive, x-private',
        'x-private': 'hop',
        'set-cookie': ['dsh-auth-other=leak; Path=/', 'app=kept; Path=/'],
      })
      res.end(`upstream ${url.pathname}`)
    })
  })
  state.server.on('upgrade', (req: IncomingMessage, socket: Socket) => {
    state.seen.push(req)
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: x\r\n\r\n',
    )
    socket.on('data', (chunk: Buffer) => socket.write(`echo:${chunk.toString('utf8')}`))
    socket.on('end', () => socket.end())
    socket.on('error', () => socket.destroy())
  })
  state.server.listen(0, '127.0.0.1')
  await once(state.server, 'listening')
  const address = state.server.address()
  if (address === null || typeof address === 'string') throw new Error('no port')
  state.origin = `http://127.0.0.1:${String(address.port)}`
  return state
}

function session(id: string): SessionView {
  return {
    id,
    kind: 'browser',
    principal: { issuer: 'https://id.example', subject: id, groups: [] },
    issuedAt: 0,
    lastUsedAt: 0,
    expiresAt: Number.MAX_SAFE_INTEGER,
    csrf: 'c',
  }
}

function fakeHost(upstream: Upstream) {
  const sessions = new Map<string, SessionView>([['alice', session('alice')]])
  const listeners = new Set<(s: SessionSummary, reason: SessionEndReason) => void>()
  const marked: string[] = []
  const signin = vi.fn((_req: IncomingMessage, res: ServerResponse) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('sign in here')
  })
  const host: GatewayHost = {
    routes: new Map([['/auth/signin', signin]]),
    session: (req) => {
      const id = /(?:^|;\s*)s=([^;]+)/u.exec(req.headers.cookie ?? '')?.[1]
      return id === undefined ? undefined : sessions.get(id)
    },
    signInPath: '/auth/signin',
    wantsNavigation: (req) => req.headers['sec-fetch-mode'] === 'navigate',
    clientIp: (req) => req.socket.remoteAddress?.replace(/^::ffff:/u, ''),
    markClientIp: (_req, ip) => marked.push(ip),
    onSessionEnd: (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    sweep: vi.fn(),
    upstream: () => new URL(upstream.origin),
    authenticatedUrl: (base) => `${base}?token=${TOKEN}`,
    publicHost: PUBLIC_HOST,
  }
  const end = (id: string) => {
    sessions.delete(id)
    for (const listener of listeners) listener(session(id), 'revoked')
  }
  return { host, end, marked, signin }
}

const opened: Array<{ stop(): Promise<void> }> = []
const servers: Server[] = []

afterEach(async () => {
  for (const item of opened.splice(0)) await item.stop()
  for (const server of servers.splice(0)) {
    server.closeAllConnections()
    await new Promise((resolve) => server.close(resolve))
  }
})

async function setup(publicPaths: string[] = []) {
  const upstream = await startUpstream()
  servers.push(upstream.server)
  const fake = fakeHost(upstream)
  const logger = { info: vi.fn(), warn: vi.fn() }
  const gateway = new Gateway({ host: '127.0.0.1', port: 0, publicPaths }, fake.host, logger)
  await gateway.start()
  opened.push(gateway)
  return { upstream, gateway, logger, ...fake, port: gateway.port! }
}

function send(
  port: number,
  path: string,
  headers: Record<string, string> = {},
  method = 'GET',
  body?: string,
): Promise<{ status: number; headers: IncomingMessage['headers']; body: string }> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { host: '127.0.0.1', port, path, method, headers: { host: PUBLIC_HOST, ...headers } },
      (response) => {
        const chunks: Buffer[] = []
        response.on('data', (chunk: Buffer) => chunks.push(chunk))
        response.on('end', () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        )
      },
    )
    request.once('error', reject)
    request.end(body)
  })
}

/** Raw upgrade request; resolves with the first bytes the gateway answers and the socket. */
async function rawUpgrade(
  port: number,
  path: string,
  cookie?: string,
): Promise<{ head: string; socket: Socket }> {
  const socket = connect({ host: '127.0.0.1', port })
  await once(socket, 'connect')
  socket.write(
    `GET ${path} HTTP/1.1\r\nHost: ${PUBLIC_HOST}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 13\r\n${cookie === undefined ? '' : `Cookie: ${cookie}\r\n`}\r\n`,
  )
  const [chunk] = (await once(socket, 'data')) as [Buffer]
  return { head: chunk.toString('utf8'), socket }
}

describe('gateway helpers', () => {
  it('recognizes loopback binds only', () => {
    for (const host of ['127.0.0.1', '127.1.2.3', '::1', '[::1]', 'localhost'])
      expect(isLoopback(host), host).toBe(true)
    for (const host of [undefined, '0.0.0.0', '::', '10.0.0.2', 'dsh.example', '128.0.0.1'])
      expect(isLoopback(host), String(host)).toBe(false)
  })

  it('matches exact public paths and star prefixes', () => {
    expect(isPublicPath('/hooks/a', ['/hooks/*'])).toBe(true)
    expect(isPublicPath('/hooks', ['/hooks/*'])).toBe(false)
    expect(isPublicPath('/ping', ['/ping'])).toBe(true)
    expect(isPublicPath('/ping/x', ['/ping'])).toBe(false)
  })

  it('normalizes the request target so the gate and DSH see one path', () => {
    expect(normalizedTarget('/a/../api/x?q=1')).toBe('/api/x?q=1')
    expect(normalizedTarget('/%2e%2e/api')).toBe('/api')
    expect(normalizedTarget('/auth/signin/../../plugins/x')).toBe('/plugins/x')
    for (const bad of [undefined, '', '*', 'http://evil/x', '//evil/x'])
      expect(normalizedTarget(bad), String(bad)).toBeUndefined()
  })

  it("replaces a client's DSH cookies with the gateway's own and keeps the rest", () => {
    expect(rewriteCookie('a=1; dsh-auth-x=stolen; b=2', NATIVE)).toBe(`a=1; b=2; ${NATIVE}`)
    expect(rewriteCookie(undefined, undefined)).toBe('')
    const headers = upstreamHeaders(
      {
        host: PUBLIC_HOST,
        connection: 'keep-alive, x-drop',
        'x-drop': '1',
        'transfer-encoding': 'chunked',
        'proxy-authorization': 'secret',
        'x-dsh-oidc-client-ip': '6.6.6.6',
        origin: 'https://dsh.example',
        'sec-fetch-site': 'same-origin',
        cookie: 'dsh-auth-y=z',
      },
      NATIVE,
      '192.0.2.9',
    )
    expect(headers).toEqual({
      host: PUBLIC_HOST,
      origin: 'https://dsh.example',
      'sec-fetch-site': 'same-origin',
      cookie: NATIVE,
      'x-dsh-oidc-client-ip': '192.0.2.9',
    })
    expect(
      downstreamHeaders({
        'set-cookie': ['dsh-auth-q=1; Path=/', ' app=2'],
        'keep-alive': 'timeout=5',
        'content-type': 'text/html',
      }),
    ).toEqual({ 'set-cookie': [' app=2'], 'content-type': 'text/html' })
  })
})

describe('gateway listener', () => {
  it('refuses to open when DSH will not mint its cookie', async () => {
    const upstream = await startUpstream()
    servers.push(upstream.server)
    upstream.mintStatus = 401
    const gateway = new Gateway(
      { host: '127.0.0.1', port: 0, publicPaths: [] },
      fakeHost(upstream).host,
      { info: vi.fn(), warn: vi.fn() },
    )
    await expect(gateway.start()).rejects.toThrow(/did not mint/u)
    expect(gateway.port).toBeUndefined()
  })

  it('turns away every signed-out request and upgrade before DSH sees it', async () => {
    const { port, upstream } = await setup()
    const navigation = await send(port, '/', { 'sec-fetch-mode': 'navigate' })
    expect(navigation).toMatchObject({ status: 303, headers: { location: '/auth/signin' } })
    for (const path of ['/', '/assets/app.js', '/plugins/x/client.js', '/plugins/events', '/api/x'])
      expect((await send(port, path)).status, path).toBe(401)
    expect((await send(port, '/connect?token=x')).status).toBe(404)
    expect((await send(port, '/auth/anything')).status).toBe(404)
    expect((await send(port, '/auth/signin/../../api/x')).status).toBe(401)
    expect((await send(port, 'http://evil/x')).status).toBe(400)
    const { head, socket } = await rawUpgrade(port, '/api/remote.mux')
    expect(head).toMatch(/^HTTP\/1\.1 401/u)
    socket.destroy()
    expect(upstream.seen).toEqual([])
  })

  it('answers its own routes in process with the client address', async () => {
    const { port, signin, marked, upstream } = await setup()
    const page = await send(port, '/auth/signin')
    expect(page).toMatchObject({ status: 200, body: 'sign in here' })
    expect(signin).toHaveBeenCalledOnce()
    expect(marked).toEqual(['127.0.0.1'])
    expect(upstream.seen).toEqual([])
  })

  it("streams a signed-in request to DSH with the gateway's cookie, never the client's", async () => {
    const { port, upstream } = await setup()
    const response = await send(
      port,
      '/api/echo?x=1',
      {
        cookie: 's=alice; dsh-auth-abc=forged',
        'content-type': 'application/json',
        'x-dsh-oidc-client-ip': '6.6.6.6',
      },
      'POST',
      '{"hello":"world"}',
    )
    expect(response.status).toBe(200)
    expect(response.body).toBe('upstream /api/echo')
    expect(response.headers['set-cookie']).toEqual(['app=kept; Path=/'])
    expect(response.headers['x-private']).toBeUndefined()
    const [seen] = upstream.seen
    expect(seen?.url).toBe('/api/echo?x=1')
    expect(seen?.headers.host).toBe(PUBLIC_HOST)
    expect(seen?.headers.cookie).toBe(`s=alice; ${NATIVE}`)
    expect(seen?.headers['x-dsh-oidc-client-ip']).toBe('127.0.0.1')
    expect(upstream.bodies).toEqual(['{"hello":"world"}'])
  })

  it('lets configured public paths through without a session', async () => {
    const { port, upstream } = await setup(['/hooks/*'])
    expect((await send(port, '/hooks/build', {}, 'POST', 'x')).status).toBe(200)
    expect((await send(port, '/hookshot')).status).toBe(401)
    expect(upstream.seen.map((req) => req.url)).toEqual(['/hooks/build'])
  })

  it('closes live WebSockets and event streams when the session ends', async () => {
    const { port, upstream, gateway, end } = await setup()
    const { head, socket } = await rawUpgrade(port, '/api/remote.mux', 's=alice')
    expect(head).toMatch(/^HTTP\/1\.1 101/u)
    expect(head.toLowerCase()).toContain('upgrade: websocket')
    expect(upstream.seen.at(-1)?.headers.cookie).toBe(`s=alice; ${NATIVE}`)
    socket.write('ping')
    const [echo] = (await once(socket, 'data')) as [Buffer]
    expect(echo.toString('utf8')).toBe('echo:ping')

    const events = await new Promise<IncomingMessage>((resolve, reject) => {
      const request = httpRequest(
        {
          host: '127.0.0.1',
          port,
          path: '/events',
          headers: { host: PUBLIC_HOST, cookie: 's=alice' },
        },
        resolve,
      )
      request.once('error', reject)
      request.end()
    })
    await once(events, 'data')
    expect(gateway.liveCount('alice')).toBe(2)

    const closed = (stream: NodeJS.EventEmitter) =>
      new Promise<void>((resolve) => {
        stream.on('error', () => undefined)
        stream.once('close', () => resolve())
      })
    const socketClosed = closed(socket)
    const streamClosed = closed(events)
    end('alice')
    await Promise.all([socketClosed, streamClosed])
    expect(gateway.liveCount('alice')).toBe(0)
    const again = await rawUpgrade(port, '/api/remote.mux', 's=alice')
    expect(again.head).toMatch(/^HTTP\/1\.1 401/u)
    again.socket.destroy()
  })

  it('answers 502 when DSH is not there', async () => {
    const { port, upstream } = await setup()
    upstream.server.closeAllConnections()
    await new Promise((resolve) => upstream.server.close(resolve))
    servers.splice(servers.indexOf(upstream.server), 1)
    expect((await send(port, '/api/x', { cookie: 's=alice' })).status).toBe(502)
    const { head, socket } = await rawUpgrade(port, '/api/remote.mux', 's=alice')
    expect(head).toMatch(/^HTTP\/1\.1 502/u)
    socket.destroy()
  })
})

describe('gateway mode through apply()', () => {
  it('waits for DSH to listen, opens the gateway, and closes it on dispose', async () => {
    const upstream = await startUpstream()
    servers.push(upstream.server)
    const probe = createServer()
    probe.listen(0, '127.0.0.1')
    await once(probe, 'listening')
    const address = probe.address()
    if (address === null || typeof address === 'string') throw new Error('no port')
    const port = address.port
    await new Promise((resolve) => probe.close(resolve))

    let ready = false
    const disposers: Array<() => unknown> = []
    const logger = { info: vi.fn(), warn: vi.fn() }
    const ctx = {
      logger,
      webServer: {
        host: '127.0.0.1',
        getOrigin: () => {
          if (!ready) {
            ready = true
            throw new Error('webserver: origin read before the listener bound a port')
          }
          return upstream.origin
        },
        register: () => () => undefined,
      },
      connection: {
        authenticatedUrl: (base: string) => `${base}?token=${TOKEN}`,
        fetch: { register: () => async () => undefined },
      },
      credentials: { resolve: async () => undefined },
      on: () => undefined,
      emit: () => undefined,
      provide: () => () => undefined,
      effect: (factory: () => unknown) => {
        const result = factory()
        if (typeof result === 'function') disposers.push(result as () => unknown)
      },
    }
    const { apply } = await import('../src/index.js')
    await apply(ctx as never, {
      issuer: 'https://id.example',
      clientId: 'client',
      publicOrigin: `https://${PUBLIC_HOST}`,
      allowAnyUser: true,
      mode: 'gateway',
      gatewayListen: `127.0.0.1:${String(port)}`,
    })
    await vi.waitFor(
      async () => {
        expect((await send(port, '/api/x')).status).toBe(401)
      },
      { timeout: 5_000, interval: 100 },
    )
    const signin = await send(port, '/auth/signin')
    expect(signin.status).toBe(200)
    expect(signin.body).toContain('Sign in')
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('gateway listening'))
    for (const dispose of disposers) await dispose()
    await vi.waitFor(async () => {
      await expect(send(port, '/auth/signin')).rejects.toThrow()
    })
  })
})
