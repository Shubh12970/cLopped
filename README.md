# cLopped - URL shortener

A TinyURL-style URL shortener built as a system-design learning project.
Paste a long URL, get a short link; visiting it returns a 302 redirect while
an asynchronous click log feeds analytics.

**Live demo:** https://clopped.2wf0w2.workers.dev

## Features

- Sequential base62 codes, custom aliases and optional random 8-character codes.
- Optional date expiry and click-count expiry. Click-count admission uses one
  conditional SQL update, not a read-then-increment race.
- Client-side QR generation; best-effort 60-second edge caching for eligible links.
- Clerk owner accounts, private owned-link stats/CSV, owner-only deletion.
- Totals, daily/hourly charts, bounded referrer/country breakdowns, CSV export.
- Revocable personal API tokens, shown once and stored as SHA-256 hashes.
- Creation limit: 30 attempts per rolling 60 minutes per IP.

## Stack

React + Vite, hand-written CSS, Cloudflare Workers, D1 (SQLite), Clerk.
No Worker web framework or chart library. Free-tier deployment; no credit card
was used for this build. Provider quotas and policies can change.

## API

| Route | Purpose |
| --- | --- |
| `POST /api/links` | Create; URL plus optional `custom_code`, `expires_at`, `max_clicks`, `code_style: "random"` |
| `GET /:code` | Redirect, or 410 ended/expired, 404 unknown |
| `GET /api/links/:code/stats` | Stats; owner-only for owned links |
| `GET /api/links/:code/clicks.csv` | Newest 5000 click rows; same privacy rule |
| `GET /api/links/mine` | Authenticated owner's links |
| `DELETE /api/links/:code` | Owner-only deletion |
| `POST /api/tokens` | Mint a personal token with a valid owner credential |
| `GET /api/tokens` | Owner's token metadata, never raw secrets |
| `DELETE /api/tokens/:id` | Revoke an owned token |

Use `Authorization: Bearer <credential>` with a Clerk session JWT or a personal
API token. Anonymous creation accepts no nonempty credential. An invalid supplied
credential is rejected with 401, never silently downgraded to anonymous creation.

## Run locally

```bash
npm install
npm run d1:migrate:local
npm run build
npx wrangler dev
```

For frontend development, `npm run dev` starts Vite. Clerk environment values
are public configuration, not passwords; configure your own instance for sign-in.

## Test and deploy

```bash
npm test
npx wrangler d1 create url_shortener  # once; use your database_id in wrangler.toml
npm run d1:migrate                  # apply remote migrations
npm run deploy
```

53 automated tests passed on 12 November 2026. The integration tests use a
purpose-built D1 stub; separate bounded checks exercised the deployed service.
A live 10-request parallel check at a click limit of 2 returned 2 redirects and
8 ended pages. This is not a load benchmark or a user-count capacity claim.

## Honest limits

Anonymous stats and CSV are public to anyone with the code. Default sequential
codes are enumerable. Click analytics can count bots/prefetch and lose failed
asynchronous writes. The click gate and analytics log can differ. Cached redirects
may survive deletion at other edge locations until the 60-second TTL expires.

Referrer grouping uses at most 100 raw groups folded to 10 hosts, so some hosts
can be undercounted. CSV quotes fields but does not neutralize spreadsheet
formulas: inspect untrusted exports in a text editor or import columns as text.
Tokens have full owner access, no narrower scopes or automatic expiry. The current
Clerk instance is a development instance; free-provider and shared-D1 limits
remain. No lakh-user capacity or universal availability guarantee is claimed.

## Documentation

The beginner-first teaching guide and progress report are mirrored in
[`docs/documentation.html`](docs/documentation.html) and
[`docs/progress-report.html`](docs/progress-report.html). Download/open the HTML
to read it; GitHub's source view does not render it as a web page.
The originals remain the living Google Docs in the project folder on Drive.
