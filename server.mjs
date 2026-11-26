// An example "Sign in with Idena" website (Idena Connect): a page with the sign-in link, and the nonce,
// authentication and disconnect endpoints, which check the signatures themselves (no Idena node needed). README.md
// explains each step. Sessions are kept in memory: a real website keeps them in its own store.
//
// Usage: node server.mjs [port, default 29780]
import http from 'node:http'
import crypto from 'node:crypto'
import {secp256k1} from '@noble/curves/secp256k1.js'
import {keccak_256 as keccak} from '@noble/hashes/sha3.js'

const PORT = Number(process.argv[2] || 29780)

// 127.0.0.1, not localhost: the app's requests could try ::1 first, where nothing listens.
const BASE = `http://127.0.0.1:${PORT}`
// token -> {address, nonce, signedIn}
const sessions = new Map()

const hex = (bytes) => Buffer.from(bytes).toString('hex')

/** The address that signed `nonce` with `signatureHex` (65 bytes r, s, v), as an Idena node's dna_signatureAddress. */
export function signerOf(nonce, signatureHex, curve = secp256k1, hash = keccak) {
  const sig = Buffer.from(signatureHex.replace(/^0x/, ''), 'hex')
  if (sig.length !== 65) throw new Error('signature is not 65 bytes')
  const digest = hash(hash(new TextEncoder().encode(nonce)))
  const recovered = new Uint8Array([sig[64], ...sig.subarray(0, 64)])
  const pub = curve.Point.fromBytes(
    curve.recoverPublicKey(recovered, digest, {prehash: false})
  ).toBytes(false)
  return `0x${hex(hash(pub.subarray(1)).subarray(12))}`
}

function signInLink(token) {
  const params = new URLSearchParams({
    token,
    callback_url: `${BASE}/done?token=${token}`,
    nonce_endpoint: `${BASE}/auth/v1/start-session`,
    authentication_endpoint: `${BASE}/auth/v1/authenticate`,
    disconnect_endpoint: `${BASE}/auth/v1/disconnect`,
    favicon_url: `${BASE}/favicon.svg`,
  })
  return `dna://signin/v1?${params}`
}

const page = (body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Idena Connect test site</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;color:#16161d}
a.button{display:inline-block;padding:10px 18px;border-radius:8px;background:#578fff;color:#fff;text-decoration:none}
code{word-break:break-all;font-size:12px}</style></head><body>${body}</body></html>`

const escape = (text) =>
  String(text).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = ''
    req.on('data', (chunk) => {
      raw += chunk
      if (raw.length > 10000) reject(new Error('too large'))
    })
    req.on('end', () => {
      try {
        resolve(JSON.parse(raw || '{}'))
      } catch (error) {
        reject(error)
      }
    })
  })
}

// The app's page calls the endpoints from its own origin (axios, JSON): the site answers the CORS preflight, as a
// real sign-in site must.
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type',
}

function send(res, status, type, body) {
  res.writeHead(status, {'content-type': type, 'cache-control': 'no-store', ...CORS})
  res.end(body)
}

const json = (res, value) => send(res, 200, 'application/json', JSON.stringify(value))

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, BASE)
  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, CORS)
      return res.end()
    }
    if (req.method === 'GET' && url.pathname === '/') {
      const token = crypto.randomUUID()
      sessions.set(token, {address: null, nonce: null, signedIn: false})
      const link = signInLink(token)
      console.log(`LINK ${link}`)
      return send(res, 200, 'text/html', page(`<h1>Idena Connect test site</h1>
<p><a class="button" href="${escape(link)}">Sign in with Idena</a></p>
<p>The link, to open in the desktop app:</p><p><code>${escape(link)}</code></p>`))
    }
    if (req.method === 'GET' && url.pathname === '/favicon.svg') {
      return send(res, 200, 'image/svg+xml',
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#578fff"/></svg>')
    }
    if (req.method === 'POST' && url.pathname === '/auth/v1/start-session') {
      const {token, address} = await readJson(req)
      const session = sessions.get(token)
      if (!session || typeof address !== 'string') return json(res, {success: false, error: 'unknown token'})
      session.address = address.toLowerCase()
      // The nonce names this site (README, section 2): the app signs it only for this site.
      session.nonce = `signin-${new URL(BASE).host}/${crypto.randomUUID()}`
      console.log(`START token=${token} address=${session.address}`)
      return json(res, {success: true, data: {nonce: session.nonce}})
    }
    if (req.method === 'POST' && url.pathname === '/auth/v1/authenticate') {
      const {token, signature} = await readJson(req)
      const session = sessions.get(token)
      if (!session?.nonce || typeof signature !== 'string') return json(res, {success: false, error: 'no session'})
      const signer = signerOf(session.nonce, signature)
      session.signedIn = signer === session.address
      console.log(`AUTH token=${token} signer=${signer} authenticated=${session.signedIn}`)
      return json(res, {success: true, data: {authenticated: session.signedIn}})
    }
    if (req.method === 'POST' && url.pathname === '/auth/v1/disconnect') {
      // Signed by the account: "disconnect-<this site's origin>-<unix seconds>", the time within 5 minutes of now.
      const {address, time, signature} = await readJson(req)
      const now = Math.floor(Date.now() / 1000)
      if (typeof address !== 'string' || !Number.isInteger(time) || typeof signature !== 'string')
        return json(res, {success: false, error: 'bad request'})
      if (Math.abs(now - time) > 300) return json(res, {success: false, error: 'time too far from now'})
      const signer = signerOf(`disconnect-${BASE}-${time}`, signature)
      if (signer !== address.toLowerCase()) return json(res, {success: false, error: 'not signed by that account'})
      let ended = 0
      for (const session of sessions.values())
        if (session.address === signer && session.signedIn) {
          session.signedIn = false
          ended += 1
        }
      console.log(`DISCONNECT address=${signer} ended=${ended}`)
      return json(res, {success: true, data: {disconnected: true}})
    }
    if (req.method === 'GET' && url.pathname === '/done') {
      const session = sessions.get(url.searchParams.get('token'))
      return send(res, 200, 'text/html', page(session?.signedIn
        ? `<h1>Signed in</h1><p>As <code>${escape(session.address)}</code>.</p>`
        : '<h1>Not signed in</h1>'))
    }
    if (req.method === 'GET' && url.pathname === '/status.json') {
      const session = sessions.get(url.searchParams.get('token'))
      return json(res, session ? {address: session.address, signedIn: session.signedIn} : null)
    }
    send(res, 404, 'text/plain', 'not found')
  } catch (error) {
    console.log(`ERROR ${error.message}`)
    send(res, 400, 'application/json', JSON.stringify({success: false, error: error.message}))
  }
})

server.listen(PORT, '127.0.0.1', () => console.log(`READY ${BASE}`))
