import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * The files a phone fetches without cookies to install the Web UI, read from
 * DSH's real frontend build: the manifest and apple-touch-icon its index
 * links, and every icon the manifest lists. Paths are absolute from the root,
 * where the index's `<base href="./">` resolves them.
 */
export function installFiles(distDirectory: string): string[] {
  const index = readFileSync(join(distDirectory, 'index.html'), 'utf8')
  const link = (rel: string) => {
    const tag = new RegExp(`<link[^>]+rel="${rel}"[^>]*>`, 'u').exec(index)?.[0]
    const href = tag === undefined ? undefined : /href="([^"]+)"/u.exec(tag)?.[1]
    if (href === undefined) throw new Error(`the frontend index links no ${rel}`)
    return new URL(href, 'https://dsh.test/').pathname
  }
  const manifest = link('manifest')
  const { icons = [] } = JSON.parse(
    readFileSync(join(distDirectory, manifest.slice(1)), 'utf8'),
  ) as { icons?: Array<{ src: string }> }
  const iconPaths = icons.map(({ src }) => new URL(src, `https://dsh.test${manifest}`).pathname)
  return [...new Set([manifest, link('apple-touch-icon'), ...iconPaths])]
}
