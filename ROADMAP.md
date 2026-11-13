# Loopback — Build Roadmap

**Cross-Layer Correlation Framework for Detecting Multi-Step Attacks in API-Driven Applications**
Testimony Chimberengwa R236592N · BSc Honors Computer Engineering · University of Zimbabwe · Supervisor: Mr Makate

> Status as of 12 Nov 2026 — the core system is **built, containerized, and verified**, now at v2 scope: the target is a full-featured vulnerable bank (blog + feedback, careers + applications, support chatbot, personal-details management) and the SOC is a comprehensive detection + response app (user tracking, manual + autonomous response actions, explainable risk engine, detailed attack-path graphs, dynamic dashboard). Remaining work: 4-config evaluation switch + the sub-2B LLM comparative classifier.

---

## 1. What Loopback is

API-layer defences (WAFs, gateways) see requests but not the data they touch; database-layer defences (DAM) see queries but not the user/session that caused them — and even pairwise request↔query correlation (US 7,640,235) scores one pair at a time. Loopback closes that gap: it **tags every SQL query with the API request that produced it**, joins the two event streams, and reasons over **ordered session sequences** to catch multi-step attacks (IDOR sweeps, enumeration, chained business-logic abuse) that every per-event detector waves through.

## 2. As-built architecture (12 Nov 2026)

Two application containers + one PostgreSQL container, wired with Docker Compose:

| Container | Port | Role | Status |
| :--- | :--- | :--- | :--- |
| `loopback-target` | 5000 | **Apex Trust Bank** — realistic vulnerable bank: REST + GraphQL, PostgreSQL, ZWL accounts, registration (500 ZWL opening deposit), transfers, statements, profiles, API keys | ✅ built + verified |
| `loopback-soc` | 5100 | **Loopback SOC** — standalone app: ingest → trace-join correlation → session sequences → rule detection → alerts + attack paths; operator console + REST/GraphQL read API | ✅ built + verified |
| `loopback-db` | 5434 host | PostgreSQL 16: `loopback` (bank) + `soc` (events/alerts) | ✅ built + verified |

Correlation flow (verified end-to-end):

1. `target/trace.js` — AsyncLocalStorage context per request → trace id → response header + SQL comments (`/* loopback: trace=… user=… op=… */`).
2. `target/db.js` `tq()` — every query executed under the trace gets stamped + recorded as a `db_event`.
3. On response finish → `POST soc:5100/ingest` with the api_event + its db_events (fire-and-forget).
4. `soc/correlate.js` — per event: load the actor's 60 s window → evaluate sequence rules (IDOR/BOLA, negative transfer, overdraft, ≥3-target enumeration, cross-functional breadth) → progressive severity (INFO→MEDIUM→HIGH→CRITICAL) → attack path (actor → endpoint → correlated SQL → target → impact) + evidence JSON → `alerts` table.
5. Console + REST + GraphQL read APIs surface live traffic with SQL pairing, alerts, and per-session loopback timelines.

## 3. Verified results (curl + browser, local and containerized)

- Registration → `ACC-1005`, 500 ZWL opening deposit ✅
- Login → dashboard, transfers, transactions, statement download, profile, API keys ✅
- Negative transfer: balance 450 → 600 ZWL (inflation) → **BIZLOGIC alert (HIGH/CRITICAL)** ✅
- Overdraft: 2 000 ZWL sent on a 600 ZWL balance → **BIZLOGIC alert** ✅
- Statement IDOR: Mary (ACC-1001) pulls John's (ACC-1002) statement → **IDOR alert** ✅
- API-key IDOR + enum sweep (ids 2–4 in <2 s) → **ENUM alert (CRITICAL)** ✅
- GraphQL: `user(2) { apiKey }`, `statement(ACC-1002)`, `transfer(amount: -75)` → same alerts, tagged with operation names ✅
- Attack path embeds the loopback SQL chain ("trace … produced: SELECT sessions… | UPDATE accounts…") ✅
- SOC GraphQL: `stats`, `alerts(severity)`, `sessions` ✅

## 4. Phase status (mapped to the Chapter 1 work plan)

| Phase | Weeks | Status |
| :--- | :--- | :--- |
| 0. Foundations — rename to Loopback, PostgreSQL migration | — | ✅ done (12 Nov) |
| 1. Standalone containerized target (REST + GraphQL, realistic bank, 500 ZWL seeds) | 3–4 | ✅ done — **v2**: + blog/feedback, careers/applications, support chatbot, personal-details management |
| 2. Trace-injection middleware + SQL comment tagging + event collection | 5–6 | ✅ done (in-process ingest; statement-log tailing kept as future work) |
| 3. Correlation engine + session-sequence layer | 7–8 | ✅ done (Node in the SOC; a standalone Python engine remains an option for the dissertation) |
| 4. Sequence + detection layer (rule-based, 4 configs) | 9–11 | ◐ rule-based detection done; the 4-config switch (api-only / db-only / correlation-only / full) still to add |
| 5. Evaluation harness (traffic generator, P/R/F1/FPR + latency) | 12–13 | ⬜ next |
| 6. SOC console + local-context validation | 14 | ✅ **v2 done**: 9-tab console (overview dashboard, live traffic, user tracking + investigations, alerts with SVG attack paths, response actions, settings, API, manual, terms), manual + autonomous response, explainable risk engine, operator-audited login. Local-context scenario pack to polish |
| 7. Lightweight AI classifier (sub-2B, comparative) | 9–11 | ◐ lightweight statistical risk engine shipped as the explainable proof-of-concept baseline; the sub-2B LLM classifier needs the labelled dataset from Phase 5 |
| 8. Write-up + defence demo | 15–16 | ⬜ `docker compose up --build -d` one-command demo ready |

## 5. Next actions (in order)

1. **Four-config switch** — env-driven detection mode in the SOC (`LOOPBACK_CONFIG=api|db|corr|full`) so the same traffic set can be scored under all four configurations.
2. **Traffic generator** — `eval/` scripts: benign browsing + the six attack scenarios at configurable rates; labelled ground truth per session.
3. **Metrics collector** — run all four configs over the same traffic, dump `metrics_runs` (TP/FP/FN/TN, precision, recall, F1, FPR, middleware latency overhead).
4. **Lightweight classifier** — once labelled data exists, compare the tiny-model classifier against the rule engine for the dissertation's Chapter 4.
5. **Screenshots** for Chapters 4–5 (portal, SOC console, attack-path modal, metrics tables).

## 6. Environment facts (this machine)

- PostgreSQL 18.4 service @ `localhost:5432` (`postgres` / `12345678`) — used by local (bare-node) runs; Docker stack ships its own postgres:16.
- Docker Desktop + compose verified working (node:22-alpine, postgres:16-alpine).
- Node v22.18.0. `psql` at `C:/Program Files/PostgreSQL/18/bin/` (not on PATH).
- Repo: github.com/zeiro123/loopback (Apache-2.0).

## 7. Open decisions

1. Standalone Python correlator for the dissertation, or keep the in-process Node engine? (Lean: keep Node for the artefact; port to Python only if the supervisor requires a separate service.)
2. Classifier choice (sub-2B class) — decide after Phase 5 produces the labelled dataset.
3. Persistence of evaluation runs — separate `metrics` schema in the `soc` database.
