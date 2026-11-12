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
     │   REST API + GraphQL on PostgreSQL · ZWL accounts · realistic  │
     │   registration, transfers, statements, profiles, API keys      │
     │                                                                │
     │   trace middleware: trace id per request → SQL comment tagging │
     └──────────────┬──────────────────────────────┬──────────────────┘
              api_events                       db_events
                    └────────────┬───────────────────┘
                 ┌───────────────▼────────────────┐
                 │   loopback-soc — SOC app       │
                 │   ingest → correlate (trace    │
                 │   join) → session sequences →  │
                 │   rule-based detection →       │
                 │   alerts + attack paths        │
                 └───────┬───────────────┬────────┘
                         │               │
                  operator console   REST + GraphQL
                  (live traffic,     read API for
                  alerts, sessions)  integrations
```

Two application containers + one PostgreSQL container (`docker-compose.yml`):

| Container | Port | Role |
| :--- | :--- | :--- |
| `loopback-target` | **5000** | Apex Trust Bank — realistic vulnerable bank (REST + GraphQL) |
| `loopback-soc` | **5100** | Loopback SOC — standalone correlation + detection app |
| `loopback-db` | 5434 (host) | PostgreSQL 16 — `loopback` (bank) + `soc` (events/alerts) databases |

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

## 5. Intentional vulnerabilities (target)

| # | Class | Where | Exploit |
| :--- | :--- | :--- | :--- |
| 1 | **BOLA / IDOR** | `GET /api/statements/:accountNumber` · `GET /api/accounts/:accountNumber/*` | Swap the account number → another client's full statement (name, address, ledger) |
| 2 | **BOLA / IDOR** | `GET /api/users/:id/apikey` | Swap the user id → another client's secret API key |
| 3 | **IDOR (write)** | `PUT /api/users/:id/email` | Modify another client's email |
| 4 | **Business logic** | `POST /api/transfers` | Negative `amount` → `balance -= (-150)` inflates the sender's balance |
| 5 | **Business logic** | `POST /api/transfers` | No insufficient-funds check → overdraft beyond the balance |
| 6 | **Enumeration** | All of the above | Sequential IDs + no rate limiting → horizontal sweeps |
| 7 | **GraphQL surface** | `/graphql` | Same flaws over GraphQL: `user(id) { apiKey }`, `statement(accountNumber)`, `transfer(amount: -75)` |

All of this is synthetic, self-contained lab data. **Do not deploy this anywhere public.**

## 6. What the SOC detects (sequence-level)

The correlator reasons over each actor's ordered 60-second session window — not single events:

| Rule | Trigger | Example alert |
| :--- | :--- | :--- |
| **IDOR / BOLA** | Resource owner ≠ authenticated actor | `Possible IDOR Attack: Unauthorized Account Object Access` |
| **Business logic** | Negative transfer, or amount > balance (overdraft) | `Business Logic Attack: Negative Amount Balance Inflation` |
| **Enumeration** | ≥3 distinct object targets in the sliding window | `Resource Enumeration: Horizontal Sweep Detected` |
| **Cross-functional** | Flagged activity spans ≥2 endpoint classes | Severity escalation (INFO → MEDIUM → HIGH → CRITICAL) |

Every alert embeds the **loopback chain**: the API request, the exact SQL it produced (joined on trace id), the object owner, and the impact — plus a step-by-step attack path (actor → endpoint → SQL → target → impact) and the raw evidence JSON.

## 7. SOC APIs

The SOC itself exposes both REST and GraphQL for programmatic access:

```bash
# login (operator gate)
curl -s -X POST http://localhost:5100/api/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}'

# REST
curl -s http://localhost:5100/api/alerts  -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:5100/api/events?limit=50  -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:5100/api/sessions -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:5100/api/stats    -H "Authorization: Bearer $TOKEN"

# GraphQL (read-only)
curl -s -X POST http://localhost:5100/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ stats { apiEvents dbEvents alerts critical } alerts(limit: 5) { severity title } }"}'
```

Ingest (what the target calls): `POST /ingest` with `{ "events": [ {kind:"api"|"db", ...} ] }` — every event carries the trace id.

The bank's own GraphQL is at `http://localhost:5000/graphql` (GraphiQL landing page included); REST endpoints live under `/api/*`.

## 8. Project layout

```
target/          Apex Trust Bank — vulnerable REST + GraphQL bank (container 1)
  server.js      REST routes + GraphQL schema/resolvers (intentional vulns)
  db.js          PostgreSQL layer + tagged queries (trace stamped into SQL)
  trace.js       trace middleware: trace ids, SQL comment tagging, SOC ingest
  public/        banking portal UI (vanilla HTML/CSS/JS)
soc/             Loopback SOC — standalone detection app (container 2)
  server.js      ingest, REST + GraphQL read API, operator console
  correlate.js   sequence-level rules engine + attack path builder
  db.js          api_events / db_events / alerts store (PostgreSQL)
  public/        SOC console UI (vanilla HTML/CSS/JS)
docker/          compose init script (second database)
legacy/          the original single-app React lab (kept for the write-up's
                 design-evolution record; superseded by target/ + soc/)
ROADMAP.md       build plan mapped to the 16-week capstone work plan
MANUAL.md        full user manual — setup, walkthroughs, attack playbook
```

## 9. How the correlation works (the "loopback")

1. A request (REST or GraphQL) arrives → `trace.js` mints a **trace id** and opens an `AsyncLocalStorage` context.
2. Every SQL statement executed while handling the request is stamped with a comment: `/* loopback: trace=<uuid> user=<id> op=<endpoint> */` — and a `db_event` is recorded on the trace.
3. When the response finishes, the target posts the **api_event + its db_events** to the SOC (`POST /ingest`).
4. The SOC stores both streams and runs the **correlator**: for each event it loads the actor's last 60 seconds, evaluates the four sequence rules, computes progressive severity, and — for every hit — joins the api and db rows on the trace id to build the evidence chain and attack path.
5. The operator console (and the REST/GraphQL API) surface the result: live traffic with SQL pairing, alerts with attack paths, and per-session loopback timelines.

## 10. Limitations

Scoped to relational PostgreSQL; the detection is rule-based (the lightweight-LLM comparative classifier is future work, per the dissertation plan); evaluation runs against synthetic traffic in this lab only; the operator gate is a lab default (`admin`/`admin`) with plain-text demo passwords — none of this is production security tooling.

## 11. License

Apache-2.0 — see [LICENSE](LICENSE).
