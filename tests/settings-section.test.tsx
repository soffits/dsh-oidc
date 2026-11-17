// @vitest-environment happy-dom
import { act, createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('@deepseek-ai/dsh-client-ui-primitives', () => ({
  Button: ({ children, ...props }: Record<string, unknown>) =>
    createElement('button', props, children as never),
  Tag: ({ children }: { children?: unknown }) => createElement('span', null, children as never),
}))
import { en, type AccountKey } from '../src/client/locales.js'
import { SignInSection, type SignInApi } from '../src/client/SignInSection.js'
import {
  describeUserAgent,
  fetchSessions,
  formatDuration,
  revokeSessions,
  type SessionEntry,
  type SignInStatus,
} from '../src/client/sessions.js'

;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const t = (key: AccountKey) => en[key]
const base = { issuer: 'https://id.example', issuedAt: 1, lastUsedAt: 2, expiresAt: 3 }
const sessions: SessionEntry[] = [
  {
    ...base,
    id: 'a'.repeat(22),
    kind: 'browser',
    subject: 'ada',
    name: 'ada',
    current: true,
    mine: true,
  },
  {
    ...base,
    id: 'b'.repeat(22),
    kind: 'browser',
    subject: 'ada',
    name: 'ada',
    userAgent:
      'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Version/18.0 Mobile Safari/604.1',
    ip: '192.0.2.4',
    current: false,
    mine: true,
  },
  {
    ...base,
    id: 'c'.repeat(22),
    kind: 'browser',
    subject: 'bo',
    name: 'bo',
    current: false,
    mine: false,
  },
]
const status: SignInStatus = {
  mode: 'forward-auth',
  issuer: 'https://id.example',
  clientId: 'client',
  publicOrigin: 'https://dsh.example',
  policy: {
    subjects: 2,
    emails: ['ada@example.test'],
    groups: ['ops'],
    groupMode: 'all',
    requiredClaims: ['tenant'],
    anyUser: false,
  },
  sessionMaxAgeSeconds: 604_800,
  sessionIdleTimeoutSeconds: 21_600,
  persistSessions: true,
  requireSessionOnApi: true,
  senderContext: false,
  directLogin: false,
  environment: ['DSH_OIDC_ISSUER', 'DSH_OIDC_CLIENT_ID'],
  audit: [
    {
      id: '1',
      at: 5,
      type: 'session-revoked',
      person: { issuer: 'x', subject: 'bo', name: 'bo' },
      by: { issuer: 'x', subject: 'ada', name: 'ada' },
    },
    { id: '2', at: 4, type: 'sign-in', person: { issuer: 'x', subject: 'ada' }, ip: '192.0.2.4' },
  ],
}

let root: Root | undefined
afterEach(() => {
  if (root !== undefined) act(() => root!.unmount())
  root = undefined
  document.body.innerHTML = ''
  vi.unstubAllGlobals()
})

async function render(api: SignInApi): Promise<HTMLElement> {
  const host = document.createElement('div')
  document.body.appendChild(host)
  root = createRoot(host)
  await act(async () => {
    root!.render(createElement(SignInSection, { t, api }))
  })
  return host
}

function buttons(host: HTMLElement, label: string): HTMLButtonElement[] {
  return [...host.querySelectorAll('button')].filter((button) => button.textContent === label)
}

describe('Sign-in settings page', () => {
  it('shows sessions, the provider summary and recent activity', async () => {
    const api: SignInApi = {
      status: vi.fn(async () => status),
      sessions: vi.fn(async () => sessions),
      revoke: vi.fn(async () => []),
    }
    const host = await render(api)
    const text = host.textContent
    expect(text).toContain('This device')
    expect(text).toContain('Safari · iPhone · 192.0.2.4')
    expect(text).toContain('Emails: ada@example.test')
    expect(text).toContain('Groups (all of): ops')
    expect(text).toContain('DSH_OIDC_ISSUER, DSH_OIDC_CLIENT_ID')
    expect(text).toContain('7 d')
    expect(text).toContain('6 h')
    expect(text).toContain('Session ended · bo (by ada)')
    // No sign-out button on this device's own row; one per other session.
    expect(buttons(host, 'Sign out')).toHaveLength(2)
    expect(buttons(host, 'Sign out my other sessions')).toHaveLength(1)
  })

  it('ends a session, or every other session of mine, and reloads', async () => {
    let list = sessions
    const api: SignInApi = {
      status: vi.fn(async () => status),
      sessions: vi.fn(async () => list),
      revoke: vi.fn(async (target: { id: string } | { others: true }) => {
        list = list.filter((s) => ('id' in target ? s.id !== target.id : s.current || !s.mine))
        return []
      }),
    }
    const host = await render(api)
    await act(async () => {
      buttons(host, 'Sign out')[1]!.click()
    })
    expect(api.revoke).toHaveBeenCalledWith({ id: 'c'.repeat(22) })
    expect(host.textContent).not.toContain('bo192')
    await act(async () => {
      buttons(host, 'Sign out my other sessions')[0]!.click()
    })
    expect(api.revoke).toHaveBeenLastCalledWith({ others: true })
    expect(buttons(host, 'Sign out')).toHaveLength(0)
    expect(buttons(host, 'Sign out my other sessions')).toHaveLength(0)
  })

  it('says so when loading or an action fails, and retries', async () => {
    let fail = true
    const api: SignInApi = {
      status: vi.fn(async () => {
        if (fail) throw new Error('offline')
        return { ...status, audit: [], policy: { ...status.policy, anyUser: true } }
      }),
      sessions: vi.fn(async () => sessions),
      revoke: vi.fn(async () => {
        throw new Error('gone')
      }),
    }
    const host = await render(api)
    expect(host.textContent).toContain("Couldn't load sign-in details.")
    fail = false
    await act(async () => {
      buttons(host, 'Try again')[0]!.click()
    })
    expect(host.textContent).toContain('Anyone the provider signs in')
    expect(host.textContent).toContain('Nothing yet.')
    await act(async () => {
      buttons(host, 'Sign out')[0]!.click()
    })
    expect(host.querySelector('[role="alert"]')?.textContent).toBe("That didn't work. Try again.")
  })
})

describe('sessions client', () => {
  it('names common browsers and systems and falls back to the raw string', () => {
    expect(describeUserAgent(undefined)).toBeUndefined()
    expect(
      describeUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0',
      ),
    ).toBe('Edge · Windows')
    expect(
      describeUserAgent('Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0'),
    ).toBe('Firefox · Linux')
    expect(describeUserAgent('curl/8.9')).toBe('curl/8.9')
    expect(formatDuration(90)).toBe('2 min')
  })

  it('sends revokes as same-origin JSON and reads the lists defensively', async () => {
    const fetcher = vi.fn(
      async (_url: string, init?: RequestInit) =>
        new Response(
          JSON.stringify(init?.method === 'POST' ? { revoked: ['x'] } : { sessions: 'no' }),
        ),
    )
    expect(await revokeSessions({ others: true }, fetcher as typeof fetch)).toEqual(['x'])
    expect(fetcher).toHaveBeenLastCalledWith('/api/dsh-oidc/sessions/revoke', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body: '{"others":true}',
    })
    expect(await fetchSessions(fetcher as typeof fetch)).toEqual([])
    const denied = vi.fn(async () => new Response('no', { status: 401 }))
    await expect(fetchSessions(denied as typeof fetch)).rejects.toThrow('HTTP 401')
    await expect(revokeSessions({ id: 'x' }, denied as typeof fetch)).rejects.toThrow('HTTP 401')
  })
})
