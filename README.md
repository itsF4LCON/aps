# APS — Edge Anti-Phishing Scanner

A phishing URL scanner on Cloudflare Workers, written in Rust (WASM), with Cloudflare D1, Workers KV,
Workers AI and an optional Google Safe Browsing lookup.

A Firefox extension scans links inline in Gmail, a live demo runs on
[xivlabs.tech](https://xivlabs.tech/#projects), and a public API is available for anyone else to
integrate.

## How a URL is judged

Every scan goes through the same pipeline. Each layer can only add risk; nothing later in the chain
can clear a URL that an earlier layer flagged.

1. **Parse.** The `url` crate normalises the URL (IDNA/punycode, IP literals, userinfo), and the
   [Public Suffix List](https://publicsuffix.org) (`psl` crate, including its private section) finds
   the registrable domain. `evil.pages.dev` is its own site, not `pages.dev`, and the full hostname
   is always what gets analysed.
2. **Trusted hosts.** A short list of exact hostnames (`accounts.google.com`, `www.paypal.com`, …)
   returns SAFE immediately. Matching is on the full hostname, so `sites.google.com` does not
   inherit trust from `google.com`. Trust is refused for shared hosts, embedded redirect URLs
   (`google.com/url?q=…`) and `user@host` tricks.
3. **URL signals** ([`src/signals.rs`](src/signals.rs)), each with a weight; a score of 60+ blocks:

   | signal | weight |
   |---|---|
   | brand lookalike: `paypa1.com`, `micros0ft.com`, `paypal-secure-login.com` (edit distance after folding homoglyphs) | 50 |
   | brand name as a subdomain of an unrelated site: `paypal.com.account-check.example` | 50 |
   | text before `@` hiding the real host | 40 |
   | raw IP address | 30 |
   | punycode hostname | 25 |
   | brand in the path of an unrelated site | 15 |
   | shared host where anyone can publish (PSL private suffixes, Google Sites/Forms/Drive, SharePoint, …) | 15 |
   | URL that carries another URL (open-redirect pattern) | 15 |
   | credential path (`/login`, `/verify`, `/account`, …) | 10 |
   | deep subdomain chain, abuse-heavy TLD | 10 each |

4. **Reputation** (optional). If the `SAFE_BROWSING_API_KEY` secret is set, the URL is looked up
   in the [Google Safe Browsing](https://developers.google.com/safe-browsing) Lookup API. A
   listing blocks outright.
5. **Language model.** Only while the score is below the threshold, Workers AI
   (`@cf/meta/llama-3.1-8b-instruct-fast`) is asked whether the URL impersonates a brand or service
   that the brand list doesn't cover. A BLOCK answer blocks. A SAFE answer changes nothing, so
   text injected into a URL can at most cause a false positive.

Reputation and model results are cached per URL (scheme, host and path) in D1. Clean results
expire after 6 hours, because domains are often registered clean and weaponised later. Flagged
results last 7 days. URL signals are recomputed on every request.

**Privacy.** Only `scheme://host/path` is sent to Safe Browsing and to the model, and only that
form is cached. The query string is never sent or stored, because email links often carry
password-reset and session tokens there.

## Limitations

- **Heuristics.** The signals and the model catch common phishing patterns, but they are not a
  reputation database. Without the Safe Browsing key, a well-built phishing page on a fresh,
  neutral-looking domain can pass.
- **Brand list.** It is short and hand-picked (names of 5+ characters to avoid false positives).
  Brands outside it rely on the model.
- **Unchecked data.** Domain age, TLS certificates and page content are not checked yet.
- **Caller identification by Origin** stops other websites' JavaScript, but any non-browser
  client can send a forged `Origin` header. Those requests still go through the rate limits.
- **Rate limits** live in Workers KV, which is eventually consistent, so the limits are
  approximate under bursts.
- **Commercial use.** The Safe Browsing API is for non-commercial use. A commercial deployment
  should use Google's Web Risk API instead.

## Auth

`/scan` requires one of:

- **Browser extension.** Recognised by its `moz-extension://` origin, no key needed. See
  [`EXTENSION_ORIGINS`](src/lib.rs).
- **Portfolio demo.** Requests from `https://xivlabs.tech` / `https://aps.xivlabs.tech`
  ([`SITE_ORIGINS`](src/lib.rs)) need no key, but get a stricter rate limit.
- **API key.** An `X-API-Key` header, generated for free via `POST /keygen` or the
  [key-generator page](https://api.xivlabs.tech) (`aps-api.html`). Keys carry 128 bits from the
  platform CSPRNG and are stored hashed (SHA-256) in D1, never in plaintext.

Requests that match none of these get `401 Unauthorized`.

## Rate limits

Fixed-window, per-IP, tracked in Workers KV:

| Endpoint  | Limit           |
|-----------|-----------------|
| `/scan`   | 30 / minute     |
| `/scan` from the portfolio demo | 5 / minute |
| `/keygen` | 3 / hour        |

`/keygen` is stricter because each call writes a new row to `api_keys`. An unlimited endpoint
would let one IP mint unbounded keys.

## API

**POST** `https://api.xivlabs.tech/scan`

```
Content-Type: application/json
X-API-Key: aps_your_key_here   # not required from the extension
```

Request:
```json
{ "url": "https://paypal.com.account-check.example/login" }
```

Response:
```json
{
  "blocked": true,
  "reason": "Brand name used as a subdomain of an unrelated site; path asks for a login or account action",
  "score": 60,
  "signals": ["brand_in_subdomain", "credential_path"]
}
```

`blocked` and `reason` are stable. `score` (0–100) and `signals` were added later; older clients
can ignore them.

**POST** `https://api.xivlabs.tech/keygen`

Response:
```json
{ "key": "aps_..." }
```

## Development

Requires Rust (with the `wasm32-unknown-unknown` target), Node.js, `worker-build` and Wrangler.

```bash
rustup target add wasm32-unknown-unknown
cargo install worker-build
npm install -g wrangler

git clone https://github.com/itsF4LCON/aps.git
cd aps

cargo test                     # unit tests run natively, no Cloudflare account needed
npx wrangler d1 execute phishing-db --local --file=./schema.sql
npx wrangler dev --remote      # --remote is required: Workers AI isn't emulated locally
```

`wrangler.toml` needs a real `RATE_LIMIT_KV` namespace ID before dev/deploy will work:

```bash
npx wrangler kv namespace create RATE_LIMIT_KV
# paste the returned id into wrangler.toml
```

Optional reputation lookups need a
[Safe Browsing API key](https://developers.google.com/safe-browsing/v4/get-started):

```bash
npx wrangler secret put SAFE_BROWSING_API_KEY
```

## Deploy

A new database:

```bash
npx wrangler d1 execute phishing-db --remote --file=./schema.sql
npx wrangler deploy
```

An existing deployment created from an older `schema.sql` also needs the new cache table:

```bash
npx wrangler d1 execute phishing-db --remote --file=./migrations/0001_verdict_cache.sql
```

After deploying, set `EXTENSION_ORIGINS` in [`src/lib.rs`](src/lib.rs) to the real extension ID
(`about:debugging` after loading unpacked) and redeploy. Otherwise the extension gets `401` from
`/scan`.

## Browser extension

The source is in `mail_aps/`, loaded separately and not part of this crate. It's Manifest V3, with
a background service worker that relays `/scan` calls. That's the only extension context whose
`fetch()` carries the real `moz-extension://` origin the API recognises; content scripts inherit
the host page's origin instead.

## Stack

Cloudflare Workers, Rust/WASM, Cloudflare D1, Cloudflare KV, Workers AI, Google Safe Browsing

## License

[MIT](LICENSE)
