import { Readable } from 'node:stream'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { describe, expect, it, vi } from 'vitest'
import type { Context } from '@deepseek-ai/cordis'
import { resolveConfig } from '../src/config.js'
import { readEnvironment } from '../src/env.js'
import { apply } from '../src/index.js'
import { isLocalRequest, localIdentity, ownAddresses } from '../src/local.js'
import type { RequestIdentityService } from '../src/identity.js'

function request(peer: string | undefined, headers: Record<string, string> = {}): IncomingMessage {
  const value = Readable.from([])
  Object.assign(value, {
    method: 'GET',
    url: '/api/x',
    headers: { host: 'dsh.example', ...headers },
    socket: { remoteAddress: peer },
  })
  return value as IncomingMessage
}

const own = new Set(['10.1.2.3', 'fd00::5', '::1'])

describe('local requests', () => {
  it('counts only peers on this host that came without the client address header', () => {
    for (const peer of [
      '127.0.0.1',
      '127.9.9.9',
      '::1',
      '::ffff:127.0.0.1',
      '10.1.2.3',
      '::ffff:10.1.2.3',
      'fd00::5',
    ])
      expect(isLocalRequest(request(peer), own), peer).toBe(true)
    for (const peer of [undefined, '10.1.2.4', '192.0.2.1', '::ffff:192.0.2.1', 'fd00::6'])
      expect(isLocalRequest(request(peer), own), String(peer)).toBe(false)
    // The gateway and a gating proxy set the header, so their requests are never local.
    expect(isLocalRequest(request('127.0.0.1', { 'x-dsh-oidc-client-ip': '192.0.2.1' }), own)).toBe(
      false,
    )
  })

  it("reads this host's interface addresses and refreshes them", () => {
    const read = vi.fn(() => ({
      eth0: [{ address: '10.9.9.9' }, { address: 'fe80::1%eth0' }],
      lo: [{ address: '127.0.0.1' }],
    })) as never
    const first = ownAddresses(1_000_000, read)
    expect([...first].sort()).toEqual(['10.9.9.9', '127.0.0.1', '::1', 'fe80::1'])
    expect(ownAddresses(1_000_001, read)).toBe(first)
    ownAddresses(1_040_000, read)
    expect(read).toHaveBeenCalledTimes(2)
    expect(localIdentity('helper')).toEqual({
      provider: 'local',
      issuer: 'local',
      id: 'helper',
      name: 'helper',
    })
  })

  it('validates localPerson and reads it from the environment', () => {
    const base = {
      issuer: 'https://id.example',
      clientId: 'c',
      publicOrigin: 'https://dsh.example',
      allowAnyUser: true,
    }
    expect(resolveConfig(base).localPerson).toBeUndefined()
    expect(resolveConfig({ ...base, localPerson: 'helper.bot' }).localPerson).toBe('helper.bot')
    for (const bad of ['-x', 'two words', 'x'.repeat(65), 'a/b'])
      expect(() => resolveConfig({ ...base, localPerson: bad }), bad).toThrow(/localPerson/u)
    expect(readEnvironment({ DSH_OIDC_LOCAL_PERSON: 'helper' }).values).toEqual({
      localPerson: 'helper',
    })
  })
})

describe('local access through apply()', () => {
  type Listener = (
    req: IncomingMessage,
    res: ServerResponse,
    next: () => Promise<void>,
  ) => Promise<void>

  async function boot(localPerson?: string) {
    const listeners: Listener[] = []
    const fetchRoutes: Array<{ path: string; fetch: (request: Request) => Promise<Response> }> = []
    let service: RequestIdentityService | undefined
    const ctx = {
      logger: { info: vi.fn(), warn: vi.fn() },
      webServer: { register: () => () => undefined },
      connection: {
        authenticatedUrl: (url: string) => url,
        fetch: {
          register: (route: (typeof fetchRoutes)[number]) => {
            fetchRoutes.push(route)
            return async () => undefined
          },
        },
      },
      credentials: { resolve: async () => undefined },
      on: (_name: string, listener: Listener) => listeners.push(listener),
      emit: () => undefined,
      provide: (_name: string, value: RequestIdentityService) => {
        service = value
      },
      effect: (factory: () => unknown) => factory(),
    }
    await apply(ctx as unknown as Context, {
      issuer: 'https://id.example',
      clientId: 'c',
      publicOrigin: 'https://dsh.example',
      allowAnyUser: true,
      ...(localPerson === undefined ? {} : { localPerson }),
    })
    /** Run the connection/request waterfall the way DSH does. */
    const through = async (req: IncomingMessage, handler: () => Promise<void>) => {
      const captured: { status?: number } = {}
      const res = {
        writeHead(status: number) {
          captured.status = status
          return res
        },
        end: () => res,
      } as unknown as ServerResponse
      const run = (index: number): Promise<void> =>
        index === listeners.length ? handler() : listeners[index]!(req, res, () => run(index + 1))
      await run(0)
      return captured.status
    }
    return { through, service: () => service!, fetchRoutes }
  }

  it('refuses a local request without a session when localPerson is unset', async () => {
    const { through } = await boot()
    const handler = vi.fn(async () => undefined)
    expect(await through(request('127.0.0.1'), handler)).toBe(401)
    expect(handler).not.toHaveBeenCalled()
  })

  it('admits a local request as localPerson and still refuses gated requests without a session', async () => {
    const { through, service, fetchRoutes } = await boot('helper')
    let seen: unknown
    await through(request('127.0.0.1'), async () => {
      seen = service().current()
    })
    expect(seen).toEqual({ provider: 'local', issuer: 'local', id: 'helper', name: 'helper' })

    const handler = vi.fn(async () => undefined)
    expect(await through(request('192.0.2.1'), handler)).toBe(401)
    expect(
      await through(request('127.0.0.1', { 'x-dsh-oidc-client-ip': '192.0.2.1' }), handler),
    ).toBe(401)
    expect(handler).not.toHaveBeenCalled()

    // The Sign-in page's endpoints answer local access too.
    const sessions = fetchRoutes.find((route) => route.path === '/api/dsh-oidc/sessions')!
    let status = 0
    await through(request('127.0.0.1'), async () => {
      status = (await sessions.fetch(new Request('http://dsh.internal/api/dsh-oidc/sessions')))
        .status
    })
    expect(status).toBe(200)
    expect(
      (await sessions.fetch(new Request('http://dsh.internal/api/dsh-oidc/sessions'))).status,
    ).toBe(401)
  })
})
