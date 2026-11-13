# Loopback

**Cross-Layer Correlation Framework for Detecting Multi-Step Attacks in API-Driven Applications**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-compose%20up%20%E2%9C%94-2496ED?logo=docker&logoColor=white)](#2-quickstart-docker--recommended)
[![Node](https://img.shields.io/badge/node-20%2B-339933?logo=node.js&logoColor=white)](#3-quickstart-local-bare-node-20)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](#2-quickstart-docker--recommended)

Loopback closes the visibility gap between API-layer and database-layer security tooling. WAFs and API gateways score single requests; DAM tools score single queries; even pairwise request↔query correlation scores one pair at a time. A multi-step attack made of individually-benign requests sails through all of them. Loopback **tags every SQL statement with the API request that produced it** (trace-injection middleware + SQL comments), joins the two event streams on the trace id, and reasons over **ordered session sequences** to surface the cumulative deviation of IDOR sweeps, horizontal enumeration, and chained business-logic abuse.

> Capstone project — Testimony Chimberengwa R236592N · BSc Honors Computer Engineering · University of Zimbabwe · Supervisor: Mr Makate

---

## 1. Architecture

```
                attacker / analyst / normal user (browser, curl, Burp)
                                     │
     ┌───────────────────────────────▼────────────────────────────────┐
     │   loopback-target — Apex Trust Bank (deliberately vulnerable)  │
     │   REST + GraphQL on PostgreSQL · ZWL accounts · 500 ZWL        │
     │   opening deposits · registration · transfers · statements     │
     │   profiles + details · developer API keys · blog + feedback    │
     │   careers + applications · support chatbot                     │
     │                                                                │
     │   trace middleware: trace id per request → SQL comment tagging │
     └──────────────┬───────────────────────────▲───────────────────┘
              api_events                control plane
              db_events                 (block user / revoke session,
                    │                    applied on every request)
     ┌───────────────▼────────────────┐
     │   loopback-soc — SOC app       │
     │   ingest → trace-join →        │
     │   session sequences → rules →  │
     │   lightweight risk engine →    │
     │   alerts + attack paths →      │
     │   AUTONOMOUS RESPONSE          │
     └───────┬───────────────┬────────┘
             │               │
      operator console   REST + GraphQL
      (overview, live    read API for
      traffic, users,    integrations
      alerts, actions,
      settings, API,
      manual, terms)
```

Two application containers + one PostgreSQL container (`docker-compose.yml`):

| Container | Port | Role |
| :--- | :--- | :--- |
| `loopback-target` | **5000** | Apex Trust Bank — realistic vulnerable bank (REST + GraphQL) |
| `loopback-soc` | **5100** | Loopback SOC — standalone correlation, detection + response app |
| `loopback-db` | 5434 (host) | PostgreSQL 16 — `loopback` (bank) + `soc` (events/alerts/actions/risk) databases |

## 2. Quickstart (Docker — recommended)

```bash
git clone https://github.com/zeiro123/loopback.git
cd loopback
docker compose up --build -d
```

Then open:

- **Banking portal** → http://localhost:5000
- **SOC console** → http://localhost:5100 (operator: `admin` / `admin`)

Reset the whole lab: `docker compose down -v && docker compose up --build -d`

## 3. Quickstart (local, bare Node 20+)

Requires a local PostgreSQL (default: `postgres://postgres:12345678@localhost:5432`). The services create their schema and seed data on boot.

```bash
cp .env.example .env          # optional — sane local defaults are built in
cd soc    && npm install && npm start   # SOC console  → http://localhost:5100
cd target && npm install && npm start   # banking app  → http://localhost:5000
```

## 4. Seeded accounts

Every seeded customer opens with a **500 ZWL** deposit. New registrations (portal or GraphQL) also start with 500 ZWL.

| Role | Username | Password | Account | Address |
| :--- | :--- | :--- | :--- | :--- |
| Customer | `Mary` | `peter` | ACC-1001 | 14 Samora Machel Avenue, Harare |
| Customer | `John` | `peter` | ACC-1002 | 82 Herbert Chitepo Street, Mutare |
| Customer | `Alice` | `peter` | ACC-1003 | 45 Joshua Nkomo Street, Bulawayo |
| Customer | `Bob` | `peter` | ACC-1004 | 12 Robert Mugabe Way, Gweru |
| SOC operator | `admin` | `admin` | — | http://localhost:5100 |

Account numbers are sequential and guessable by design — that is part of the lab.

## 5. The vulnerable target — what you can test

**Realistic banking (REST + GraphQL):** registration, login, dashboard, transfers (quick amounts + memos), transaction history, official statement download (holder details + address + ledger), profile settings with personal-details updates (phone, address, occupation), developer API keys.

**Company surface:** a blog with client feedback (comments), a careers page with five seeded openings and job applications with cover letters, and a rule-based support chatbot that answers balance/transfer/statement/careers questions.

**Intentional vulnerabilities:**

| # | Class | Where | Exploit |
| :--- | :--- | :--- | :--- |
| 1 | **BOLA / IDOR** | `GET /api/statements/:accountNumber` · `GET /api/accounts/:accountNumber/*` | Swap the account number → another client's full statement (name, address, ledger) |
| 2 | **BOLA / IDOR** | `GET /api/users/:id/apikey` · `GET /api/users/:id` | Swap the user id → another client's secret API key / full PII (email, phone, address) |
| 3 | **IDOR (write)** | `PUT /api/users/:id/email` · `PUT /api/users/:id/details` | Modify another client's email or personal details |
| 4 | **Business logic** | `POST /api/transfers` | Negative `amount` → `balance -= (-150)` inflates the sender's balance |
| 5 | **Business logic** | `POST /api/transfers` | No insufficient-funds check → overdraft beyond the balance |
| 6 | **Enumeration** | All of the above | Sequential IDs + no rate limiting → horizontal sweeps |
| 7 | **IDOR** | `GET /api/applications/:id` · `DELETE /api/applications/:id` · GraphQL `application(id)` | Read/withdraw any applicant's cover letter + PII by numeric id |
| 8 | **Chatbot data leak** | `POST /api/support/chat` | Mention any account number ("what is the balance of ACC-1001?") → the bot reads back another client's balance |
| 9 | **GraphQL surface** | `/graphql` | Same flaws over GraphQL: `user(id) { apiKey }`, `statement(accountNumber)`, `application(id)`, `transfer(amount: -75)` |

All of this is synthetic, self-contained lab data. **Do not deploy this anywhere public.**

## 6. The SOC — what it gives the operator

**Nine tabs:** Overview (dynamic threat dashboard) · Live Traffic · Users · Alerts · Response Actions · Settings · API · Manual · Terms.

- **User tracking** — every actor: client ID, username, IPs, devices (user-agents), request volume, endpoint classes, error counts, alerts, live risk score, ACTIVE/BLOCKED status, first/last seen. The investigation view shows the user's risk breakdown, full activity log (every request with its SQL), their alerts, and their action history.
- **Detection (sequence-level)** — the correlator reasons over each actor's ordered 60-second window: IDOR/BOLA (owner ≠ actor), business logic (negative transfer, overdraft), enumeration (≥3 distinct targets), cross-functional escalation. Progressive severity INFO → MEDIUM → HIGH → CRITICAL.
- **Detailed attack paths** — each alert renders a layered data-traversal graph: **device (IP + user-agent) → session → API endpoint (server) → correlated SQL → database tables + rows → impact**, plus a 6-step chronological sequence.
- **Response actions** — from any alert or the user view: **Block User** (kills all live sessions immediately, locks login, HTTP 403 on every bank call), **Revoke Session** (kills one token), **Dismiss**. Every action is logged with operator, reason and alert reference.
- **Autonomous response** — a configurable policy (Settings): when an alert crosses the severity threshold or the risk engine scores a user above the threshold, the SOC blocks the user and revokes their sessions **on its own**, logging the reason (thresholds met, trace id, alert reference).
- **Lightweight risk engine (AI proof of concept)** — a transparent, explainable statistical model scoring every tracked user 0–100 over seven weighted features (velocity, target breadth, IDOR hits, business-logic hits, error rate, cross-functional breadth, data volume). Every score decomposes into per-feature contributions the operator can read — the honest lightweight baseline the dissertation's sub-2B LLM classifier will be compared against.
- **Dynamic threat dashboard** — live counters (events, SQL, alerts, high/critical, tracked users, blocks, autonomous actions, avg risk), severity distribution bars, risk leaderboard, latest alerts + actions; auto-refresh.
- **Operator login is audited too** — the SOC records its own logins (and failed attempts) with IP and user-agent.

## 7. SOC APIs

The SOC itself exposes both REST and GraphQL:

```bash
# operator login
curl -s -X POST http://localhost:5100/api/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}'

# REST (Bearer token or X-API-Key)
curl -s http://localhost:5100/api/stats   -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:5100/api/users   -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:5100/api/users/1 -H "Authorization: Bearer $TOKEN"   # investigation view
curl -s http://localhost:5100/api/alerts  -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:5100/api/actions -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:5100/api/settings -H "Authorization: Bearer $TOKEN"

# apply a response action
curl -s -X POST http://localhost:5100/api/actions -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"kind":"block_user","value":"2","reason":"manual block from API"}'

# GraphQL (read-only)
curl -s -X POST http://localhost:5100/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ stats { apiEvents alerts blockedUsers autonomousActions } users { username risk riskLevel } actions(source: \"autonomous\") { kind reason } }"}'
```

**Control plane (SOC → target):** the SOC pushes block/revoke commands to the target's `POST /api/soc/controls` (shared `X-SOC-Key`); the target enforces them on every request and on every login. **Ingest (target → SOC):** `POST /ingest` with `{kind: "api"|"db", traceId, actorId, username, ip, userAgent, api, operation, params, resourceOwner, meta}` — every event carries the trace id.

The bank's own GraphQL is at `http://localhost:5000/graphql` (GraphiQL included); REST endpoints live under `/api/*`.

## 8. Project layout

```
target/          Apex Trust Bank — vulnerable REST + GraphQL bank (container 1)
  server.js      REST routes (banking, blog, careers, chat, control plane)
  graphql.js     GraphQL schema/resolvers (same bank, second surface)
  db.js          PostgreSQL layer + tagged queries (trace stamped into SQL)
  trace.js       trace middleware: trace ids, SQL comment tagging, SOC ingest
  chatbot.js     rule-based support assistant (hardcoded instructions)
  controls.js    SOC control-plane endpoint (block/revoke enforcement)
  public/        banking portal UI (vanilla HTML/CSS/JS, 9 tabs)
soc/             Loopback SOC — standalone detection + response app (container 2)
  server.js      ingest, tracking, actions, settings, REST + GraphQL read API
  correlate.js   sequence-level rules engine + detailed attack path builder
  risk.js        lightweight statistical risk model (explainable, 7 features)
  controls.js    response push to target + autonomous response policy
  db.js          api_events / db_events / alerts / actions / risk / settings
  public/        SOC console UI (vanilla HTML/CSS/JS, 9 tabs, SVG attack graphs)
docker/          compose init script (second database)
legacy/          the original single-app React lab (design-evolution record)
ROADMAP.md       build plan mapped to the 16-week capstone work plan
MANUAL.md        full user manual — setup, walkthroughs, attack playbook
```

## 9. How the correlation works (the "loopback")

1. A request (REST or GraphQL) arrives → `trace.js` mints a **trace id** and opens an `AsyncLocalStorage` context.
2. Every SQL statement executed while handling the request is stamped with a comment: `/* loopback: trace=<uuid> user=<id> op=<endpoint> */` — and a `db_event` is recorded on the trace.
3. When the response finishes, the target posts the **api_event + its db_events** to the SOC (`POST /ingest`), including IP, user-agent and session token.
4. The SOC stores both streams and runs the **correlator**: for each event it loads the actor's last 60 seconds, evaluates the sequence rules, computes progressive severity, joins the api and db rows on the trace id, and builds the evidence chain + attack path (device → session → API → SQL → tables → impact).
5. The **risk engine** re-scores the actor over a 10-minute window; the **autonomous-response policy** compares alerts and risk scores against the configured thresholds and blocks/revokes on its own when warranted.
6. The operator console (and the REST/GraphQL API) surface the result: live traffic with SQL pairing, per-user investigations, alerts with attack paths, and the full action audit.

## 10. Limitations

Scoped to relational PostgreSQL; the risk engine is a transparent statistical model, not an LLM (the sub-2B comparative classifier is dissertation future work); evaluation runs against synthetic traffic in this lab only; the operator gate is a lab default (`admin`/`admin`) with plain-text demo passwords — none of this is production security tooling.

## 11. License

Apache-2.0 — see [LICENSE](LICENSE).
