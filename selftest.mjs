// Self-test of server.mjs without the app: a random key signs in as the app would (start-session, the node's
// doubleHash signature, authenticate; the nonce names the site and serves once, the token keeps its address), then
// disconnects (a stale time and another key's signature refused).
// Usage: node selftest.mjs [port], with server.mjs running.
import {secp256k1} from '@noble/curves/secp256k1.js'
import {keccak_256 as keccak} from '@noble/hashes/sha3.js'

const BASE = `http://127.0.0.1:${process.argv[2] || 29780}`
const hex = (b) => Buffer.from(b).toString('hex')
const post = async (path, body) =>
  (await fetch(BASE + path, {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body)})).json()

const html = await (await fetch(BASE + '/')).text()
const link = new URL(html.match(/href="(dna:[^"]+)"/)[1].replaceAll('&#38;', '&'))
const token = link.searchParams.get('token')
const key = secp256k1.utils.randomSecretKey()
const pub = secp256k1.getPublicKey(key, false)
const address = `0x${hex(keccak(pub.subarray(1)).subarray(12))}`
const sign = (nonce, k) => {
  const rec = secp256k1.sign(keccak(keccak(new TextEncoder().encode(nonce))), k, {prehash: false, format: 'recovered'})
  return hex(new Uint8Array([...rec.subarray(1), rec[0]]))
}
const {data: {nonce}} = await post('/auth/v1/start-session', {token, address})
const good = await post('/auth/v1/authenticate', {token, signature: sign(nonce, key)})
const status = await (await fetch(`${BASE}/status.json?token=${token}`)).json()
// The nonce names this site; it serves once; a signed-in token keeps its address.
const named = nonce.startsWith(`signin-${new URL(BASE).host}/`)
const replay = await post('/auth/v1/authenticate', {token, signature: sign(nonce, key)})
const swap = await post('/auth/v1/start-session', {token, address: '0x' + '1'.repeat(40)})
const kept = await (await fetch(`${BASE}/status.json?token=${token}`)).json()
// A control: another key's signature is refused.
const html2 = await (await fetch(BASE + '/')).text()
const token2 = new URL(html2.match(/href="(dna:[^"]+)"/)[1].replaceAll('&#38;', '&')).searchParams.get('token')
const {data: {nonce: nonce2}} = await post('/auth/v1/start-session', {token: token2, address})
const bad = await post('/auth/v1/authenticate', {token: token2, signature: sign(nonce2, secp256k1.utils.randomSecretKey())})
// Disconnect: another key's signature is refused, the account's own ends its session.
const time = Math.floor(Date.now() / 1000)
const message = `disconnect-${BASE}-${time}`
const refused = await post('/auth/v1/disconnect', {address, time, signature: sign(message, secp256k1.utils.randomSecretKey())})
const stale = await post('/auth/v1/disconnect', {address, time: time - 3600, signature: sign(`disconnect-${BASE}-${time - 3600}`, key)})
const disconnected = await post('/auth/v1/disconnect', {address, time, signature: sign(message, key)})
const after = await (await fetch(`${BASE}/status.json?token=${token}`)).json()
const reuse = await post('/auth/v1/start-session', {token, address})
const ok =
  good.data.authenticated === true && status.signedIn === true && bad.data.authenticated === false &&
  named && reuse.success === false && replay.success === false && swap.success === false && kept.address === address && kept.signedIn === true &&
  refused.success === false && stale.success === false && disconnected.data?.disconnected === true && after.signedIn === false
console.log(JSON.stringify({nonce, reuse: reuse.error, replay: replay.error, swap: swap.error, good: good.data, status, bad: bad.data, refused: refused.error, stale: stale.error, disconnected: disconnected.data, after}))
console.log(ok ? 'SELFTEST PASS' : 'SELFTEST FAIL')
process.exit(ok ? 0 : 1)
