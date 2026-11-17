/**
 * The few static files a browser fetches without cookies, so they must load
 * before anyone signs in: the web app manifest and the icons it lists, and
 * the home-screen icon iOS fetches when a page is added to the Home Screen.
 * Browsers request these with credentials omitted (Chromium and WebKit fetch
 * the manifest that way unless the link opts in, and WebKit always fetches
 * touch icons that way), so behind a sign-in check they would answer 401 and
 * installing DSH as an app breaks.
 *
 * Entries are exact paths, never patterns, and only plain image or manifest
 * file names are accepted, so the list cannot open anything that carries data.
 */

/** DSH's own manifest, the icons it lists, and its apple-touch-icon. */
export const DEFAULT_PUBLIC_PATHS: readonly string[] = [
  '/manifest.webmanifest',
  '/apple-touch-icon.png',
  '/icon-192.png',
  '/icon-512.png',
  '/icon-maskable-512.png',
]

/** At most this many entries; the list is meant to stay short enough to read. */
export const MAX_PUBLIC_PATHS = 32

const STATIC_FILE = /^(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)+\.(?:webmanifest|png|svg|ico|webp)$/u

/** First path segments that carry data, sign-in or live connections. */
const RESERVED_SEGMENTS = new Set(['api', 'plugins', 'auth', 'connect', '_dsh-oidc'])

/** A validated set of exact paths that need no session for GET and HEAD. */
export interface PublicPaths {
  readonly entries: readonly string[]
  /** Whether a request with this method and normalized path may go through without a session. */
  allows(method: string | undefined, path: string): boolean
}

/** Validate the configured entries; anything that isn't a plain static file path throws. */
export function publicPaths(values: readonly string[]): PublicPaths {
  if (values.length > MAX_PUBLIC_PATHS)
    throw new Error(`dsh-oidc: publicPaths takes at most ${String(MAX_PUBLIC_PATHS)} entries`)
  if (new Set(values).size !== values.length)
    throw new Error('dsh-oidc: publicPaths contains duplicates')
  for (const value of values) {
    const first = value.split('/', 2)[1] ?? ''
    if (!STATIC_FILE.test(value) || RESERVED_SEGMENTS.has(first))
      throw new Error(
        `dsh-oidc: publicPaths entry ${JSON.stringify(value)} must be the exact path of a static manifest or image file (.webmanifest, .png, .svg, .ico, .webp), outside /api, /plugins, /auth, /connect and /_dsh-oidc`,
      )
  }
  const entries = [...values]
  const set = new Set(entries)
  return {
    entries,
    allows(method, path) {
      return (method === 'GET' || method === 'HEAD') && set.has(path)
    },
  }
}

/**
 * The request target as an origin-form path and query, normalized the way
 * WHATWG URL parsing does (dot segments resolved), so a decision is made on
 * the same path DSH routes. Undefined for anything that isn't origin-form.
 */
export function normalizedTarget(raw: string | undefined): string | undefined {
  if (raw === undefined || !raw.startsWith('/') || raw.startsWith('//')) return undefined
  try {
    const url = new URL(raw, 'http://target.invalid')
    if (url.origin !== 'http://target.invalid') return undefined
    return `${url.pathname}${url.search}`
  } catch {
    return undefined
  }
}

/** The path part of a {@link normalizedTarget}. */
export function targetPath(target: string): string {
  return target.split('?', 1)[0]!
}
