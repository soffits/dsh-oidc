// Gateway mode against a real DSH release, with no proxy in front: the
// plugin's own TLS listener is the only way in and DSH listens on loopback.
import { execFileSync, spawn, type ChildProcess } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { request as httpsRequest } from 'node:https'
import { connect as netConnect, createServer } from 'node:net'
import { networkInterfaces } from 'node:os'
import { dirname, join } from 'node:path'
import { connect as tlsConnect } from 'node:tls'
import type { Browser, BrowserContext, Page } from 'playwright'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { installFiles } from './support/install-files.js'
import { startSyntheticProvider, type SyntheticProvider } from './support/synthetic-provider.js'

const runRoot = required('DSH_OIDC_RUN_ROOT')
const runtime = required('DSH_OIDC_RUNTIME')
const dshHome = required('DSH_HOME')
const stackRoot = join(runRoot, 'gateway-stack')
const screenshotDirectory = process.env.DSH_OIDC_SCREENSHOT_DIR
const CLIENT_ID = 'synthetic-client'
const SECRET_REF = 'DSH_OIDC_TEST_CLIENT_SECRET'
const SESSION_COOKIE = '__Host-dsh-oidc-session'

let provider: SyntheticProvider | undefined
let dsh: ChildProcess | undefined
let browser: Browser | undefined
let dshOutput = ''
let gatewayPort = 0
let dshPort = 0
let publicOrigin = ''
let assetPath = ''
let installPaths: string[] = []
let certPath = ''
let keyPath = ''

function required(name: string): string {
  const value = process.env[name]
  if (value === undefined || value === '') throw new Error(`GATEWAY_BLOCKED: ${name} is required`)
  return value
}

const delay = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds))

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') return reject(new Error('no port'))
      server.close(() => resolve(address.port))
    })
  })
}

/** One request to the gateway, as a client with no cookie unless given one. */
function gateway(
  path: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; location?: string; body: string }> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      {
        host: '127.0.0.1',
        port: gatewayPort,
        path,
        servername: 'dsh.test',
        rejectUnauthorized: false,
        headers: { host: `dsh.test:${String(gatewayPort)}`, ...headers },
        signal: AbortSignal.timeout(5_000),
      },
      (response) => {
        const chunks: Buffer[] = []
        // An event stream that answered 200 would never end; one chunk is enough.
        response.on('data', (chunk: Buffer) => {
          chunks.push(chunk)
          if (response.headers['content-type']?.includes('event-stream') === true)
            response.destroy()
        })
        const done = () =>
          resolve({
            status: response.statusCode ?? 0,
            ...(response.headers.location === undefined
              ? {}
              : { location: response.headers.location }),
            body: Buffer.concat(chunks).toString('utf8'),
          })
        response.on('end', done)
        response.on('close', done)
      },
    )
    request.once('error', reject)
    request.end()
  })
}

/** A raw WebSocket upgrade through the gateway; resolves with the status line. */
async function upgrade(path: string, cookie = ''): Promise<string> {
  const socket = tlsConnect({
    host: '127.0.0.1',
    port: gatewayPort,
    servername: 'dsh.test',
    rejectUnauthorized: false,
  })
  await once(socket, 'secureConnect')
  socket.write(
    `GET ${path} HTTP/1.1\r\nHost: dsh.test:${String(gatewayPort)}\r\nOrigin: ${publicOrigin}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\n${cookie === '' ? '' : `Cookie: ${cookie}\r\n`}\r\n`,
  )
  const [chunk] = (await once(socket, 'data')) as [Buffer]
  socket.destroy()
  return chunk.toString('utf8').split('\r\n', 1)[0] ?? ''
}

function writeCertificate(): void {
  certPath = join(stackRoot, 'cert.pem')
  keyPath = join(stackRoot, 'key.pem')
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:prime256v1',
      '-nodes',
      '-days',
      '1',
      '-subj',
      '/CN=dsh.test',
      '-addext',
      'subjectAltName=DNS:dsh.test,IP:127.0.0.1',
      '-keyout',
      keyPath,
      '-out',
      certPath,
    ],
    { stdio: 'ignore' },
  )
  chmodSync(keyPath, 0o600)
}

async function startDsh(): Promise<void> {
  const secret = randomBytes(32).toString('base64url')
  writeFileSync(
    join(dshHome, '.credentials.yaml'),
    `version: 1\nrefs:\n  ${SECRET_REF}: '${secret}'\n`,
    {
      mode: 0o600,
    },
  )
  writeFileSync(join(dshHome, 'profiles/web/cordis.patch.yml'), '[]\n', { mode: 0o600 })
  provider = await startSyntheticProvider({
    cert: readFileSync(certPath, 'utf8'),
    key: readFileSync(keyPath, 'utf8'),
    clientId: CLIENT_ID,
    clientSecret: secret,
  })
  const child = spawn(
    join(runtime, 'node_modules/.bin/dsh'),
    [
      '--profile',
      'web',
      '--no-open',
      '--host',
      '127.0.0.1',
      '--port',
      String(dshPort),
      '--trusted-host',
      `dsh.test:${String(gatewayPort)}`,
    ],
    {
      env: {
        ...process.env,
        DSH_HOME: dshHome,
        HOME: join(stackRoot, 'user-home'),
        XDG_CONFIG_HOME: join(stackRoot, 'user-config'),
        XDG_DATA_HOME: join(stackRoot, 'user-data'),
        DSH_TELEMETRY_DISABLED: '1',
        NODE_EXTRA_CA_CERTS: certPath,
        DSH_OIDC_ISSUER: provider.issuer,
        DSH_OIDC_CLIENT_ID: CLIENT_ID,
        DSH_OIDC_CLIENT_SECRET_REF: SECRET_REF,
        DSH_OIDC_PUBLIC_ORIGIN: `${publicOrigin}/`,
        DSH_OIDC_ALLOWED_SUBJECTS: JSON.stringify([
          { issuer: provider.issuer, subject: 'synthetic-operator' },
        ]),
        DSH_OIDC_MODE: 'gateway',
        DSH_OIDC_GATEWAY_LISTEN: `127.0.0.1:${String(gatewayPort)}`,
        DSH_OIDC_GATEWAY_TLS_CERT: certPath,
        DSH_OIDC_GATEWAY_TLS_KEY: keyPath,
        PATH: `${join(runtime, 'node_modules/.bin')}:${process.env.PATH ?? ''}`,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  )
  dsh = child
  const consume = (chunk: Buffer) => {
    dshOutput = (dshOutput + String(chunk).replace(/([?&]token=)[^\s&]+/gu, '$1<redacted>')).slice(
      -16_384,
    )
  }
  child.stdout.on('data', consume)
  child.stderr.on('data', consume)
  const deadline = Date.now() + 90_000
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`DSH exited early\n${dshOutput}`)
    try {
      if ((await gateway('/auth/signin')).status === 200) return
    } catch {
      // The gateway opens once DSH listens and minted its cookie.
    }
    await delay(100)
  }
  throw new Error(`gateway readiness deadline exceeded\n${dshOutput}`)
}

async function signIn(context: BrowserContext): Promise<Page> {
  const page = await context.newPage()
  await page.goto(`${publicOrigin}/`, { waitUntil: 'domcontentloaded' })
  expect(new URL(page.url()).pathname).toBe('/auth/signin')
  await page.click('a[href^="/auth/login"]')
  await page.waitForURL(`${publicOrigin}/`, { waitUntil: 'domcontentloaded' })
  await page.locator('[data-dsh-oidc-account]').waitFor({ state: 'visible', timeout: 60_000 })
  return page
}

beforeAll(async () => {
  rmSync(stackRoot, { recursive: true, force: true })
  mkdirSync(join(stackRoot, 'user-home'), { recursive: true, mode: 0o700 })
  const frontend = join(runtime, 'node_modules/@deepseek-ai/dsh-web-frontend/package.json')
  const index = readFileSync(join(dirname(frontend), 'dist/index.html'), 'utf8')
  const asset = /<script[^>]+src="([^"?]+\.js)"/u.exec(index)?.[1]
  if (asset === undefined) throw new Error('real frontend asset not found')
  assetPath = new URL(asset, 'https://dsh.test/').pathname
  installPaths = installFiles(join(dirname(frontend), 'dist'))
  gatewayPort = await freePort()
  dshPort = await freePort()
  publicOrigin = `https://dsh.test:${String(gatewayPort)}`
  writeCertificate()
  await startDsh()
  const playwright = await import('playwright')
  browser = await playwright.chromium.launch({
    headless: true,
    args: ['--host-resolver-rules=MAP dsh.test 127.0.0.1'],
  })
}, 150_000)

afterAll(async () => {
  await browser?.close()
  if (dsh !== undefined && dsh.exitCode === null) {
    const exited = once(dsh, 'exit')
    dsh.kill('SIGTERM')
    const result = await Promise.race([exited, delay(8_000).then(() => 'timeout' as const)])
    if (result === 'timeout') dsh.kill('SIGKILL')
  }
  await provider?.close()
  rmSync(stackRoot, { recursive: true, force: true })
}, 30_000)

describe(
  `gateway mode on DSH ${process.env.DSH_OIDC_DSH_VERSION ?? ''}`,
  { concurrent: false },
  () => {
    it('keeps DSH on loopback and never prints the launch token', async () => {
      expect(dshOutput).not.toContain('?token=')
      for (const addresses of Object.values(networkInterfaces()))
        for (const address of addresses ?? []) {
          if (address.internal || address.family !== 'IPv4') continue
          const reached = await new Promise<boolean>((resolve) => {
            const socket = netConnect({ host: address.address, port: dshPort })
            socket.once('connect', () => {
              socket.destroy()
              resolve(true)
            })
            socket.once('error', () => resolve(false))
          })
          expect(reached, address.address).toBe(false)
        }
    })

    it('turns away every cookieless request and upgrade', async () => {
      const navigation = await gateway('/', { 'sec-fetch-mode': 'navigate', accept: 'text/html' })
      expect(navigation).toMatchObject({ status: 303, location: '/auth/signin' })
      for (const path of [
        '/',
        assetPath,
        '/plugins/@soffits/dsh-oidc/client.js',
        '/plugins/events',
        '/api/__missing__',
        '/api/dsh-oidc/sessions',
        '/?token=guess',
      ])
        expect((await gateway(path)).status, path).toBe(401)
      expect((await gateway('/connect?token=guess')).status).toBe(404)
      expect((await gateway('/auth/nothing')).status).toBe(404)
      expect(await upgrade('/api/remote.mux')).toMatch(/^HTTP\/1\.1 401/u)
      // A DSH cookie a client made up or kept from elsewhere is dropped, not trusted.
      expect((await gateway('/api/__missing__', { cookie: 'dsh-auth-x=forged' })).status).toBe(401)
    })

    it('serves the manifest and the icons it lists to a cookieless phone, and nothing more', async () => {
      expect(installPaths).toContain('/manifest.webmanifest')
      expect(installPaths).toContain('/apple-touch-icon.png')
      for (const path of installPaths) expect((await gateway(path)).status, path).toBe(200)
      const manifest = JSON.parse((await gateway('/manifest.webmanifest')).body) as {
        start_url?: string
      }
      expect(manifest.start_url).toBe('./')
      for (const path of [
        '/favicon.svg',
        '/manifest.webmanifest/../api/__missing__',
        '/api/notify-inbox/sw.js',
      ])
        expect((await gateway(path)).status, path).toBe(401)
      expect(await upgrade('/manifest.webmanifest')).toMatch(/^HTTP\/1\.1 401/u)
    })

    it('signs in through the gateway with no DSH cookie or launch token in the browser', async () => {
      const context = await browser!.newContext({ ignoreHTTPSErrors: true })
      try {
        const page = await signIn(context)
        const cookies = await context.cookies(publicOrigin)
        expect(cookies.map((cookie) => cookie.name)).toContain(SESSION_COOKIE)
        expect(cookies.filter((cookie) => cookie.name.startsWith('dsh-auth-'))).toEqual([])
        const api = await page.evaluate(async () => {
          const response = await fetch('/api/dsh-oidc/sessions')
          return {
            status: response.status,
            body: (await response.json()) as { sessions: unknown[] },
          }
        })
        expect(api.status).toBe(200)
        expect(api.body.sessions).toHaveLength(1)
        const opened = await page.evaluate(
          (url) =>
            new Promise<boolean>((resolve) => {
              const socket = new WebSocket(url)
              socket.onopen = () => {
                socket.close()
                resolve(true)
              }
              socket.onerror = () => resolve(false)
            }),
          `wss://dsh.test:${String(gatewayPort)}/api/remote.mux`,
        )
        expect(opened).toBe(true)
        if (screenshotDirectory !== undefined) {
          mkdirSync(screenshotDirectory, { recursive: true })
          await page.screenshot({ path: join(screenshotDirectory, 'gateway-signed-in.png') })
        }
      } finally {
        await context.close()
      }
    })

    it("closes another browser's live WebSocket when its session is revoked", async () => {
      const first = await browser!.newContext({ ignoreHTTPSErrors: true })
      const second = await browser!.newContext({ ignoreHTTPSErrors: true })
      try {
        const victim = await signIn(first)
        await victim.evaluate(
          (url) => {
            const state = window as unknown as { closedAt?: number; open?: boolean }
            const socket = new WebSocket(url)
            socket.onopen = () => {
              state.open = true
            }
            socket.onclose = () => {
              state.closedAt = Date.now()
            }
          },
          `wss://dsh.test:${String(gatewayPort)}/api/remote.mux`,
        )
        await victim.waitForFunction(() => (window as unknown as { open?: boolean }).open === true)

        const actor = await signIn(second)
        const revoked = await actor.evaluate(async () => {
          const listed = (await (await fetch('/api/dsh-oidc/sessions')).json()) as {
            sessions: Array<{ id: string; current: boolean }>
          }
          const target = listed.sessions.find((session) => !session.current)
          const response = await fetch('/api/dsh-oidc/sessions/revoke', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ id: target?.id }),
          })
          return response.status
        })
        expect(revoked).toBe(200)
        await victim.waitForFunction(
          () => (window as unknown as { closedAt?: number }).closedAt !== undefined,
          undefined,
          { timeout: 10_000 },
        )
        const after = await victim.evaluate(
          async () => (await fetch('/api/dsh-oidc/sessions')).status,
        )
        expect(after).toBe(401)
      } finally {
        await first.close()
        await second.close()
      }
    })
  },
)
