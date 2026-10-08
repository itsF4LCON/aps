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
   inherit trust from `google.com`. Trust is refused for anything with a query string or a
   redirect-style path (`/url`, `/amp/`, …), for shared hosts and for `user@host` tricks. Those
   URLs go through the full analysis instead. `github.com` is deliberately not trusted, because
   release downloads and raw files there are user content.
3. **URL signals** ([`src/signals.rs`](src/signals.rs)), each with a weight; a score of 60+ blocks:

   | signal | weight |
   |---|---|
   | brand lookalike: `paypa1.com`, `micros0ft.com`, Cyrillic `аррӏе.com`, or a brand name on a domain the brand doesn't own (`paypal.support`) | 50 |
   | brand name or lookalike as a subdomain of an unrelated site: `paypal.com.account-check.example` | 50 |
   | combosquat: a brand plus a support or login word, `paypal-verify.pages.dev`, `appleid-help.com` | 45 |
   | exact brand name on a country domain missing from the brand's list (`paypal.at`): often the real company, so weaker | 30 |
   | text before `@` hiding the real host | 40 |
   | raw IP address | 30 |
   | punycode hostname | 25 |
   | domain registered less than 30 days ago (from RDAP, see below) | 25 |
   | brand in the path of an unrelated site | 15 |
   | shared host where anyone can publish (PSL private suffixes, Google Sites/Forms/Drive, SharePoint, …) | 15 |
   | URL that carries another URL (open-redirect pattern) | 15 |
   | login or account words in the hostname: `secure-login`, `verify-account` | 15 |
   | credential path (`/login`, `/verify`, `/account`, …) | 10 |
   | deep subdomain chain, abuse-heavy TLD | 10 each |

4. **Phishing feed.** A cron trigger pulls the [OpenPhish](https://openphish.com) community feed
   into D1 twice a day, shortly after each update, and keeps entries for 3 days after they
   leave it. A scan matches on its exact URL (without query string), or on its whole host unless
   the host is shared: a phishing kit usually owns its host, but on `*.pages.dev` or an S3 bucket
   the next page belongs to someone else. A listing blocks outright. This check runs before the
   cache is read, so a URL cached as clean is still caught once it is listed. (URLhaus was left
   out: it lists malware downloads, not phishing, and its ~30k entries would cost far more D1
   writes per refresh.)
5. **Reputation** (optional). If the `SAFE_BROWSING_API_KEY` secret is set, the URL is looked up
   in the [Google Safe Browsing](https://developers.google.com/safe-browsing) Lookup API. A
   listing blocks outright.
6. **Language model.** Only while the score is below the threshold, Workers AI
   (`@cf/meta/llama-3.1-8b-instruct-fast`) is asked whether the URL impersonates a brand or service
   that the brand list doesn't cover. A BLOCK answer blocks. A SAFE answer changes nothing, so
   text injected into a URL can at most cause a false positive.

Reputation and model results are cached per URL (scheme, host and path) in D1. Clean results
expire after 6 hours, because domains are often registered clean and weaponised later. Flagged
results last 7 days. URL signals are recomputed on every request.

Who scanned a URL first doesn't matter. The cache holds only what Safe Browsing and the model say
about the URL itself, and the model never sees the page. Scanning your own domain while it is
still harmless and weaponising it later gets you the same answers a later scan would. The only
thing that can go stale is a clean Safe Browsing result, for at most 6 hours.

Lookalikes are found by comparing against a list of brands after decoding punycode and folding
lookalike characters (Cyrillic, Greek, accented Latin, `0`→`o`, `rn`→`m`, …) to ASCII. Who owns a
brand is decided by a list of its real registrable domains, never by the name alone.

Domain age comes from [RDAP](https://about.rdap.org), the successor of WHOIS. The registry's
server is found through IANA's bootstrap file (cached for a day), and the registration date is
cached per domain in D1 for 30 days. It runs in parallel with the cache read and Safe Browsing,
with a 1.5 s limit. A new domain alone never blocks: new businesses register domains every day.
It counts only together with other signals, for example a fresh `secure-login.example.top/login`
scores 60. IPs and shared hosts are skipped, and so are TLDs without an RDAP server (several
country codes, `.de` among them).

If Safe Browsing, RDAP or Workers AI is unavailable, the scan still returns a verdict from what
it has, and that result is not cached, so the next scan retries.

**Privacy.** Only `scheme://host/path` is sent to Safe Browsing and to the model, and only that
form is cached. The query string is never sent or stored, because email links often carry
password-reset and session tokens there. Some services put such tokens in the path instead
(`/reset/<token>`), and those **are** sent and cached. The domain registry sees only the
registered domain (`example.co.uk`), never the hostname or path.

## Evaluation

How well does the URL alone give phishing away? [`examples/eval.rs`](examples/eval.rs) runs the
deterministic layer (trusted hosts, then URL signals and the verdict, exactly as `/scan` does)
over known phishing and known legitimate URLs. Safe Browsing, the phishing feed, domain age and
the model are left out: they need the network, and the feed is the phishing set itself.

- **Phishing:** every URL in the [OpenPhish](https://openphish.com) community feed from
  2026-09-09 to 2026-10-08 (12,807 URLs on 9,870 hosts, feed commit `ddee277`).
- **Legitimate:** the top 10,000 domains of the [Tranco](https://tranco-list.eu) list `K9Z7W`,
  as `https://domain/`.

| | URLs | blocked | rate |
|---|---:|---:|---:|
| phishing | 12,807 | 520 | **4.1% detection** |
| phishing, one URL per host | 9,870 | 467 | 4.7% detection |
| legitimate | 10,000 | 0 | **0.00% false positives** |

The URL signals are tuned to never block a real site on their own, and they don't. They catch
only phishing that names a brand in its URL, which is a small share. Most OpenPhish URLs sit on
shared hosting (47% fire `shared_host`) or on throwaway domains with neutral names. Those URLs
look like anything else from the outside, and catching them is left to the reputation feed,
Safe Browsing, domain age and the model.

Caveats: the legitimate set is bare homepages, the easiest case. Real links carry paths and
subdomains, so the real false-positive rate is higher. Precision depends on the mix of phishing
and legitimate traffic, so detection and false-positive rates are given instead.

The model was not part of this run, since it costs a call per URL. In a spot check while timing
the deployed Worker, it blocked 1 of 24 legitimate Tranco domains (`nya5.com`, as a
"typosquat"). Its BLOCK answers are a real source of false positives.

To reproduce:

```bash
eval/fetch.sh 30 10000     # downloads into eval/data (git-ignored)
cargo run --release --example eval -- eval/data/phish.txt eval/data/benign.txt
```

## Latency

Measured on 2026-10-08 from Belgium, served by Cloudflare's Paris location with D1 in Western
Europe: median time to first byte as the client sees it, including the network.

| request | median |
|---|---:|
| network baseline (a `401`, no work done) | 38 ms |
| trusted host | 90 ms |
| cached URL, from the extension | 99 ms |
| cached URL, with an API key (one more D1 query) | 136 ms |
| new URL on a known domain (model call) | 469 ms |
| new URL on a new domain (RDAP + model) | 673 ms |

A cached scan is a few D1 queries in sequence (key check, feed, then cache and domain age in
parallel), not a single lookup. Most of the time for a new URL is the model.

## Limitations

- **Heuristics.** The signals and the model catch common phishing patterns, but they are not a
  reputation database. Without the Safe Browsing key, a well-built phishing page on a fresh,
  neutral-looking domain can pass.
- **Brand list.** It is short and hand-picked (names of 5+ characters to avoid false positives).
  Brands outside it rely on the model. A country domain missing from a brand's list scores 30,
  so a real login page there doesn't block, but neither does a phishing domain like
  `paypal.com.co`. Those are left to Safe Browsing and the model.
- **Lookalike folding** covers the scripts used in common IDN attacks, not all of Unicode's
  confusables.
- **Registries in the PSL's private section** (`uk.com`, `eu.com`, …) count as shared hosts.
- **Unchecked data.** TLS certificates and page content are not checked yet. Domain age is
  unknown for TLDs without RDAP.
- **Caller identification by Origin** stops other websites' JavaScript, but it is not
  authentication: any non-browser client can send a forged `Origin` header. A key couldn't
  fix that, because anything shipped inside the extension can be extracted, and keys are free
  anyway. So the extension and demo paths are treated as public. A forged extension origin
  shares the limit an API key gets (30/minute per client), and a forged demo origin gets 5/minute.
  Forging saves a `/keygen` call and gains nothing else.
- **Rate limits are approximate.** `/scan` uses Cloudflare's Rate Limiting binding, which counts
  per Cloudflare location and is eventually consistent by design, so a client spread over many
  locations, or a fast burst, can get a little past the limit. `/keygen` uses Workers KV, which
  is eventually consistent too. Exact global limits would need a Durable Object.
- **Query strings on trusted hosts.** Any URL with a query string, even
  `accounts.google.com/signin?continue=…`, goes through the full analysis, which costs a
  lookup and possibly a model call.
- **Cache misses cost money.** The cache is per URL, so a client that scans random paths misses
  it every time, and each miss can cost a Safe Browsing lookup and a model call. Only the
  per-client rate limits bound this.
- **Commercial use.** The Safe Browsing API and the OpenPhish community feed are for
  non-commercial use only. A commercial deployment should use Google's Web Risk API and a paid feed.

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

Per client, where a client is an IPv4 address or an IPv6 /64 prefix, since one IPv6 connection
can usually pick any address in its /64. `/scan` uses Cloudflare's
[Rate Limiting binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/),
configured in [`wrangler.toml`](wrangler.toml). `/keygen` needs an hourly window, longer than the
binding allows, so it uses a fixed window in Workers KV:

| Endpoint  | Limit           |
|-----------|-----------------|
| `/scan`   | 30 / minute     |
| `/scan` from the portfolio demo | 5 / minute |
| `/keygen` | 3 / hour        |

`/keygen` is stricter because each call writes a new row to `api_keys`. An unlimited endpoint
would let one IP mint unbounded keys. Extra keys buy no extra scans, since `/scan` is limited per
client and not per key.

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
  "reason": "Brand name used as a subdomain of an unrelated site; hostname contains login or account words; path asks for a login or account action",
  "score": 75,
  "signals": ["brand_in_subdomain", "credential_host", "credential_path"]
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

URLs cached as clean before the key was set are re-checked only when their 6-hour entry
expires.

## Deploy

A new database:

```bash
npx wrangler d1 execute phishing-db --remote --file=./schema.sql
npx wrangler deploy
```

An existing deployment created from an older `schema.sql` needs the newer tables:

```bash
npx wrangler d1 migrations apply phishing-db --remote
```

The feed table fills at the next cron run (00:20 or 12:20 UTC). Locally, run
`npx wrangler dev --test-scheduled` and open `/__scheduled` to fill it right away.

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
