import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { createServer, type Server } from 'node:https'
import { exportJWK, importPKCS8, SignJWT } from 'jose'

/**
 * A minimal OpenID provider for acceptance runs: discovery, JWKS, an
 * authorize page that bounces straight back like a consent page would, and a
 * token endpoint that checks the client secret and PKCE.
 */
export interface SyntheticProvider {
  readonly server: Server
  readonly issuer: string
  /** The `sub` the next token carries; change it to test a denied identity. */
  subject: string
  close(): Promise<void>
}

export async function startSyntheticProvider(options: {
  readonly cert: string
  readonly key: string
  readonly clientId: string
  readonly clientSecret: string
}): Promise<SyntheticProvider> {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const signingKey = await importPKCS8(
    privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    'RS256',
  )
  const jwk = { ...(await exportJWK(publicKey)), kid: 'synthetic-key', alg: 'RS256', use: 'sig' }
  const codes = new Map<string, { challenge: string; nonce: string }>()
  const server = createServer({ cert: options.cert, key: options.key })
  const provider: SyntheticProvider = {
    server,
    issuer: '',
    subject: 'synthetic-operator',
    close: async () => {
      server.closeAllConnections()
      await new Promise((resolve) => server.close(resolve))
    },
  }
  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body))
  }
  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', provider.issuer)
    if (url.pathname === '/.well-known/openid-configuration')
      return json(res, 200, {
        issuer: provider.issuer,
        authorization_endpoint: new URL('authorize', provider.issuer).href,
        token_endpoint: new URL('token', provider.issuer).href,
        jwks_uri: new URL('jwks', provider.issuer).href,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post'],
      })
    if (url.pathname === '/jwks') return json(res, 200, { keys: [jwk] })
    if (url.pathname === '/authorize') {
      const state = url.searchParams.get('state')
      const nonce = url.searchParams.get('nonce')
      const challenge = url.searchParams.get('code_challenge')
      const redirectUri = url.searchParams.get('redirect_uri')
      if (state === null || nonce === null || challenge === null || redirectUri === null)
        return json(res, 400, { error: 'invalid_request' })
      const code = randomUUID()
      codes.set(code, { challenge, nonce })
      const callback = new URL(redirectUri)
      callback.searchParams.set('code', code)
      callback.searchParams.set('state', state)
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end(
        `<!doctype html><meta http-equiv="refresh" content="0;url=${callback.href.replaceAll('&', '&amp;')}">`,
      )
      return
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      const chunks: Buffer[] = []
      for await (const chunk of req) chunks.push(chunk as Buffer)
      const body = new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
      const code = body.get('code')
      const grant = code === null ? undefined : codes.get(code)
      if (code !== null) codes.delete(code)
      const verifier = body.get('code_verifier') ?? ''
      if (
        body.get('client_secret') !== options.clientSecret ||
        body.get('client_id') !== options.clientId ||
        grant === undefined ||
        grant.challenge !== createHash('sha256').update(verifier).digest('base64url')
      )
        return json(res, 400, { error: 'invalid_client' })
      const now = Math.floor(Date.now() / 1000)
      const idToken = await new SignJWT({
        iss: provider.issuer,
        sub: provider.subject,
        name: 'Synthetic Operator',
        preferred_username: 'synthetic',
        email: 'operator@example.test',
        aud: options.clientId,
        nonce: grant.nonce,
        iat: now,
        exp: now + 300,
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'synthetic-key' })
        .sign(signingKey)
      return json(res, 200, { access_token: 'synthetic', token_type: 'Bearer', id_token: idToken })
    }
    res.writeHead(404).end()
  }
  server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    handle(req, res).catch(() => res.writeHead(500).end())
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('provider bind failed')
  ;(provider as { issuer: string }).issuer = `https://127.0.0.1:${String(address.port)}/`
  return provider
}
