import { describe, expect, it } from 'vitest'
import {
  DEFAULT_PUBLIC_PATHS,
  MAX_PUBLIC_PATHS,
  normalizedTarget,
  publicPaths,
  targetPath,
} from '../src/public-paths.js'

describe('public paths', () => {
  it('lists exactly the files a phone fetches without cookies to install DSH', () => {
    expect(DEFAULT_PUBLIC_PATHS).toEqual([
      '/manifest.webmanifest',
      '/apple-touch-icon.png',
      '/icon-192.png',
      '/icon-512.png',
      '/icon-maskable-512.png',
    ])
  })

  it('allows GET and HEAD of an exact entry and nothing else', () => {
    const paths = publicPaths(DEFAULT_PUBLIC_PATHS)
    expect(paths.allows('GET', '/manifest.webmanifest')).toBe(true)
    expect(paths.allows('HEAD', '/icon-192.png')).toBe(true)
    for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS', 'get', undefined])
      expect(paths.allows(method, '/manifest.webmanifest'), String(method)).toBe(false)
    for (const path of [
      '/',
      '/index.html',
      '/favicon.svg',
      '/manifest.webmanifest/',
      '/manifest.webmanifest/x',
      '/Manifest.webmanifest',
      '/manifest%2Ewebmanifest',
      '/icon-192.png.map',
      '/api/notify-inbox/sw.js',
    ])
      expect(paths.allows('GET', path), path).toBe(false)
  })

  it('accepts only plain static file paths outside the data and sign-in routes', () => {
    expect(publicPaths(['/favicon.ico', '/brand/logo.svg', '/a_b-c.webp']).entries).toHaveLength(3)
    for (const entry of [
      '',
      '/',
      'icon.png',
      '/index.html',
      '/app.js',
      '/data.json',
      '/icons/*',
      '/icons/*.png',
      '/a/../icon.png',
      '/./icon.png',
      '/.hidden.png',
      '//icon.png',
      '/icon.png?v=1',
      '/icon%20x.png',
      ' /icon.png',
      '/api/notify-inbox/icon.png',
      '/plugins/events.png',
      '/auth/logo.png',
      '/connect/x.png',
      '/_dsh-oidc/x.png',
    ])
      expect(() => publicPaths([entry]), JSON.stringify(entry)).toThrow(/publicPaths entry/u)
    expect(() => publicPaths(['/a.png', '/a.png'])).toThrow(/duplicates/u)
    const many = Array.from({ length: MAX_PUBLIC_PATHS + 1 }, (_, i) => `/i${String(i)}.png`)
    expect(() => publicPaths(many)).toThrow(/at most/u)
  })

  it('normalizes the request target so the decision and DSH see one path', () => {
    expect(normalizedTarget('/a/../api/x?q=1')).toBe('/api/x?q=1')
    expect(normalizedTarget('/%2e%2e/api')).toBe('/api')
    expect(normalizedTarget('/icon-192.png/../../api/x')).toBe('/api/x')
    expect(normalizedTarget('/auth/signin/../../plugins/x')).toBe('/plugins/x')
    expect(targetPath('/manifest.webmanifest?v=1')).toBe('/manifest.webmanifest')
    for (const bad of [undefined, '', '*', 'http://evil/x', '//evil/x'])
      expect(normalizedTarget(bad), String(bad)).toBeUndefined()
  })
})
