/** Browser half of the `/api/dsh-oidc/*` endpoints behind the Sign-in settings page. */

export const STATUS_PATH = '/api/dsh-oidc/status'
export const SESSIONS_PATH = '/api/dsh-oidc/sessions'
export const REVOKE_PATH = '/api/dsh-oidc/sessions/revoke'

export interface SessionEntry {
  readonly id: string
  readonly kind: string
  readonly issuer: string
  readonly subject: string
  readonly name?: string
  readonly email?: string
  readonly userAgent?: string
  readonly ip?: string
  readonly issuedAt: number
  readonly lastUsedAt: number
  readonly expiresAt: number
  readonly current: boolean
  readonly mine: boolean
}

export interface AuditPerson {
  readonly issuer: string
  readonly subject: string
  readonly name?: string
}

export interface AuditEntry {
  readonly id: string
  readonly at: number
  readonly type: string
  readonly person?: AuditPerson
  readonly by?: AuditPerson
  readonly session?: string
  readonly ip?: string
  readonly userAgent?: string
}

export interface SignInStatus {
  readonly mode: string
  readonly issuer: string
  readonly clientId: string
  readonly publicOrigin: string
  readonly policy: {
    readonly subjects: number
    readonly emails: readonly string[]
    readonly groups: readonly string[]
    readonly groupMode: string
    readonly requiredClaims: readonly string[]
    readonly anyUser: boolean
  }
  readonly sessionMaxAgeSeconds: number
  readonly sessionIdleTimeoutSeconds: number
  readonly persistSessions: boolean
  readonly requireSessionOnApi: boolean
  readonly senderContext: boolean
  readonly directLogin: boolean
  readonly environment: readonly string[]
  readonly audit: readonly AuditEntry[]
}

const JSON_HEADERS = { accept: 'application/json' }

async function getJson<T>(fetcher: typeof fetch, path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetcher(path, {
    credentials: 'same-origin',
    headers: JSON_HEADERS,
    cache: 'no-store',
    ...(signal === undefined ? {} : { signal }),
  })
  if (!response.ok) throw new Error(`HTTP ${String(response.status)}`)
  return (await response.json()) as T
}

export function fetchStatus(fetcher: typeof fetch = fetch, signal?: AbortSignal) {
  return getJson<SignInStatus>(fetcher, STATUS_PATH, signal)
}

export async function fetchSessions(
  fetcher: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<SessionEntry[]> {
  const body = await getJson<{ sessions?: unknown }>(fetcher, SESSIONS_PATH, signal)
  return Array.isArray(body.sessions) ? (body.sessions as SessionEntry[]) : []
}

/** End one session by id, or every other session of the caller with `{ others: true }`. */
export async function revokeSessions(
  target: { id: string } | { others: true },
  fetcher: typeof fetch = fetch,
): Promise<string[]> {
  const response = await fetcher(REVOKE_PATH, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { ...JSON_HEADERS, 'content-type': 'application/json' },
    body: JSON.stringify(target),
  })
  if (!response.ok) throw new Error(`HTTP ${String(response.status)}`)
  const body = (await response.json()) as { revoked?: unknown }
  return Array.isArray(body.revoked) ? (body.revoked as string[]) : []
}

const BROWSERS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\bEdg(?:e|A|iOS)?\//u, 'Edge'],
  [/\bOPR\//u, 'Opera'],
  [/\bFirefox\/|\bFxiOS\//u, 'Firefox'],
  [/\bChrome\/|\bCriOS\//u, 'Chrome'],
  [/\bVersion\/[\d.]+.*\bSafari\//u, 'Safari'],
]

const SYSTEMS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\biPhone\b/u, 'iPhone'],
  [/\biPad\b/u, 'iPad'],
  [/\bAndroid\b/u, 'Android'],
  [/\bCrOS\b/u, 'ChromeOS'],
  [/\bMac OS X\b|\bMacintosh\b/u, 'macOS'],
  [/\bWindows\b/u, 'Windows'],
  [/\bLinux\b/u, 'Linux'],
]

/** "Firefox on Windows" from a User-Agent; the raw string when it's neither. */
export function describeUserAgent(userAgent: string | undefined): string | undefined {
  if (userAgent === undefined || userAgent === '') return undefined
  const browser = BROWSERS.find(([pattern]) => pattern.test(userAgent))?.[1]
  const system = SYSTEMS.find(([pattern]) => pattern.test(userAgent))?.[1]
  if (browser !== undefined && system !== undefined) return `${browser} · ${system}`
  return browser ?? system ?? userAgent.slice(0, 60)
}

/** A short human duration such as "7 d", "6 h" or "45 min". */
export function formatDuration(seconds: number): string {
  if (seconds % 86_400 === 0) return `${String(seconds / 86_400)} d`
  if (seconds % 3_600 === 0) return `${String(seconds / 3_600)} h`
  return `${String(Math.round(seconds / 60))} min`
}
