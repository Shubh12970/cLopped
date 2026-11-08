# snip - URL shortener

A TinyURL-style URL shortener, built as a system-design learning project.
Paste a long link, get a short one like `https://<host>/1Bc`; anyone visiting
it is 302-redirected to the original while the click is logged for analytics.

**Live demo:** https://url-shortener.2wf0w2.workers.dev

## Stack

| Piece | Choice | Why |
| --- | --- | --- |
| Frontend | React + Vite | Same stack as the StudyFlow dashboard; Vite gives a fast dev server and a static build the Worker can serve. |
| API + redirect | Cloudflare Workers | Free tier, no credit card; runs at the edge so redirects answer in milliseconds. |
| Database | Cloudflare D1 (SQLite) | Real SQL (the design calls for a links table with an index on `code`); serverless and free. |
| Short codes | base62 of the sequential row id | Collision-free by construction; no uniqueness-check-and-retry loop like random hashes need. |

No custom web framework on the Worker and no CSS framework: the project is
small enough that plain `fetch` routing and hand-written CSS keep every line
understandable - which is the point of a learning build.

## API

```
POST /api/links              { "url": "https://...", "custom_code": "optional" }
                             -> 201 { "code": "1Bc", "short_url": "...", "long_url": "..." }
GET  /api/links              -> { "links": [{ "code", "long_url", "created_at", "clicks" }] }
GET  /api/links/:code/stats  -> { "code", "long_url", "total_clicks", "by_day": [...], "recent": [...] }
GET  /:code                  -> 302 Location: <long_url>   (click logged async)
```

## Run locally

```bash
npm install
npm run d1:migrate:local   # create the local D1 tables
npm run dev                # Vite dev server for the frontend
npx wrangler dev           # full stack: Worker + local D1 + built assets
```

## Deploy

```bash
npx wrangler d1 create url_shortener   # once; put the database_id in wrangler.toml
npm run d1:migrate                     # create the remote tables
npm run deploy
```

## Design notes

The full build documentation (step-by-step decisions, alternatives, testing,
interview reasoning) lives in the project folder on Google Drive next to this
code archive.
