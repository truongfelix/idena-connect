# Idena Connect: add "Sign in with Idena" to your website

People sign in to your website with their Idena account, from the Idena desktop app: no password, no email, and
your server needs no Idena node. The app also keeps the list of websites a person signed in to (Settings → Idena
Connect), and can ask your website to end that sign-in (Disconnect).

This repository explains the protocol as the [community Idena desktop app](https://github.com/truongfelix/idena-desktop)
uses it, and holds a small working example server (`server.mjs`, Node.js) with a self-test.

## How a sign-in goes

```
Your page                      Idena desktop app                       Your server
---------                      -----------------                       -----------
"Sign in with Idena" link ---> opens a dialog: website, account
                               person clicks Confirm
                               POST nonce_endpoint {token, address} -> remembers the address for this token,
                                                                    <- answers a fresh nonce "signin-…"
                               the node signs the nonce
                               POST authentication_endpoint
                                    {token, signature}             -> recovers the signer from the signature;
                                                                      signer == address: the token is signed in
                                                                    <- {authenticated: true}
                               opens callback_url in the browser  -> your page sees the token is signed in
```

The token is how your page and your server recognise the same sign-in: your page makes it, puts it in the link, and
asks your server whether it is signed in (or your server sets a session cookie on the callback page).

## 1. The link

```
dna://signin/v1?token=<random>
  &callback_url=<https://your.site/after-sign-in?token=…>
  &nonce_endpoint=<https://your.site/auth/v1/start-session>
  &authentication_endpoint=<https://your.site/auth/v1/authenticate>
  &favicon_url=<https://your.site/favicon.png>
  &disconnect_endpoint=<https://your.site/auth/v1/disconnect>    (optional, section 5)
```

Every value is URL-encoded. Both endpoints must be `https:` (or `http:` for a test on your own computer). Keep the
nonce endpoint, the authentication endpoint and the disconnect endpoint on the same host: the app names your
website by the host that receives the signature, and shows a red warning when the nonce comes from another host.

## 2. The nonce endpoint

`POST nonce_endpoint` with JSON `{"token": "…", "address": "0x…"}`. Remember the address for that token and answer:

```json
{"success": true, "data": {"nonce": "signin-<random>"}}
```

The nonce must start with `signin-` (the app refuses any other). Make it random, use it once, and let it expire
after a few minutes. To refuse, answer `{"success": false, "error": "<message>"}`: the app shows the message.

## 3. The authentication endpoint

`POST authentication_endpoint` with JSON `{"token": "…", "signature": "0x…"}`.

The signature is 65 bytes: `r` (32), `s` (32), `v` (1, the recovery id 0 or 1), made by the person's Idena node
(`dna_sign`, its default format "doubleHash") over:

```
hash = keccak256(keccak256(utf8(nonce)))
```

Recover the public key from the signature and the hash (secp256k1), and the address from the key
(`0x` + the last 20 bytes of `keccak256(uncompressed public key without its first byte)`), as Ethereum does. When it
equals the address given for that token, the token is signed in:

```json
{"success": true, "data": {"authenticated": true}}
```

In JavaScript with [@noble/curves](https://github.com/paulmillr/noble-curves) and
[@noble/hashes](https://github.com/paulmillr/noble-hashes) (`server.mjs`, `signerOf`):

```js
import {secp256k1} from '@noble/curves/secp256k1.js'
import {keccak_256} from '@noble/hashes/sha3.js'

function signerOf(message, signatureHex) {
  const sig = Buffer.from(signatureHex.replace(/^0x/, ''), 'hex') // r, s, v
  const hash = keccak_256(keccak_256(new TextEncoder().encode(message)))
  const recovered = new Uint8Array([sig[64], ...sig.subarray(0, 64)]) // noble wants v first
  const pub = secp256k1.Point.fromBytes(
    secp256k1.recoverPublicKey(recovered, hash, {prehash: false})
  ).toBytes(false)
  return '0x' + Buffer.from(keccak_256(pub.subarray(1)).subarray(12)).toString('hex')
}
```

Any language with secp256k1 recovery and keccak-256 works the same way (Go: go-ethereum's `crypto.Ecrecover`;
Python: `coincurve` or `eth-keys` with `pycryptodome`'s keccak). The address is all you learn: to know whether it is
a validated Idena identity, ask a node or the Idena API (`dna_identity` / `/api/Identity/<address>`).

## 4. CORS

The app calls your endpoints from its own window, with JSON. Your server must answer the browser's preflight
(`OPTIONS`) and every answer with:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: content-type
```

Without them the app shows "Network Error" and nothing reaches your server.

## 5. Disconnect (optional)

With a `disconnect_endpoint` in the link (on the same site as the authentication endpoint), the app shows
**Disconnect** next to your website in Settings → Idena Connect. It then sends:

`POST disconnect_endpoint` with JSON `{"address": "0x…", "time": <unix seconds>, "signature": "0x…"}`

where the signature (same format as above) is over the text:

```
disconnect-<your site's origin>-<time>        e.g.  disconnect-https://your.site-1795650000
```

Your server checks that the signer is `address`, that the origin is its own (the origin of the authentication
endpoint, scheme and host, no trailing slash), and that `time` is within 5 minutes of its clock; it then ends every
session of that address and answers:

```json
{"success": true, "data": {"disconnected": true}}
```

The app then removes your website from its list. The origin and the time keep the signature from serving on another
website or another day.

## Try it

```
npm install
node server.mjs            # http://127.0.0.1:29780
node selftest.mjs          # a random key signs in, then disconnects: SELFTEST PASS
```

Open http://127.0.0.1:29780 in a browser with the Idena desktop app running, and click "Sign in with Idena". The
server prints each step (`START`, `AUTH`, `DISCONNECT`).

## Security notes

- A sign-in proves the person holds the address's key at that moment, nothing more. Bind the nonce to its token,
  use it once and let it expire.
- The person sees the host that receives the signature: serve the endpoints from the website people know.
- Never ask for a private key or a seed phrase: the app never needs to give one.

## License

MIT, see `LICENSE`.
