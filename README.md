# APS — Edge Anti-Phishing Scanner

Sub-15ms phishing URL scanner on Cloudflare Workers, using Rust (WASM), Cloudflare D1, Workers AI (Llama 3.1), and Workers KV.

A browser extension (Chrome + Firefox) scans links inline in Gmail; a public API is available for anyone else to integrate.

## How it works

1. Check if the domain is in D1.
2. If yes, return the cached verdict (<15ms, refreshed every 7 days).
3. If no, classify it with Workers AI (`@cf/meta/llama-3.1-8b-instruct-fast`).
4. Save the result to D1 for next time.

## Auth

`/scan` requires one of:

- **Browser extension** — trusted automatically via its `chrome-extension://` / `moz-extension://` origin, no key needed. See [`EXTENSION_ORIGINS`](src/lib.rs) — both browsers use a different scheme/ID for the same extension, so both must be listed.
- **API key** — a `X-API-Key` header, generated for free via `POST /keygen` or the [key-generator page](https://api.xivlabs.tech) (`aps-api.html`). Keys are stored hashed (SHA-256) in D1, never in plaintext.

Requests that match neither get `401 Unauthorized`.

## Rate limits

Fixed-window, per-IP, tracked in Workers KV:

| Endpoint  | Limit           |
|-----------|-----------------|
| `/scan`   | 30 / minute     |
| `/keygen` | 3 / hour        |

`/keygen` is stricter since each call writes a new row to `api_keys` — an unlimited endpoint would let one IP mint unbounded keys.

## API

**POST** `https://api.xivlabs.tech/scan`

```
Content-Type: application/json
X-API-Key: aps_your_key_here   # not required from the extension
```

Request:
```json
{ "url": "https://example.com" }
```

Response:
```json
{ "blocked": false, "reason": "string" }
```

**POST** `https://api.xivlabs.tech/keygen`

Response:
```json
{ "key": "aps_..." }
```

## Setup

Requires Rust (`wasm32-unknown-unknown` target), Node.js, `worker-build`, and Wrangler.

```bash
rustup target add wasm32-unknown-unknown
cargo install worker-build
npm install -g wrangler

git clone https://github.com/itsF4LCON/aps.git
cd aps

npx wrangler d1 execute phishing-db --local --file=./schema.sql
npx wrangler dev --remote   # --remote is required: Workers AI isn't emulated locally
```

`wrangler.toml` needs a real `RATE_LIMIT_KV` namespace ID before dev/deploy will work:

```bash
npx wrangler kv namespace create RATE_LIMIT_KV
# paste the returned id into wrangler.toml
```

## Deploy

```bash
npx wrangler d1 execute phishing-db --remote --file=./schema.sql
npx wrangler deploy
```

After deploying, set `EXTENSION_ORIGINS` in [`src/lib.rs`](src/lib.rs) to the real extension IDs (`chrome://extensions` / `about:debugging` after loading unpacked) and redeploy — otherwise the extension gets `401` from `/scan`.

## Browser extension

Source: `mail_aps/` (loaded separately, not part of this crate). Manifest V3, with a background service worker that relays `/scan` calls — that's the only extension context whose `fetch()` carries the real `chrome-extension://`/`moz-extension://` origin the API trusts; content scripts inherit the host page's origin instead.

## Stack

Cloudflare Workers, Rust/WASM, Cloudflare D1, Cloudflare KV, Workers AI

## License

MIT
