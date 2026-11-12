/**
 * Apex Trust Bank — PostgreSQL data layer for the Loopback vulnerable target.
 *
 * Every query executed through tq() is stamped with a SQL comment carrying the
 * active trace id and actor — that comment is what the Loopback SOC engine uses
 * to bind database activity back to the API request that produced it.
 */
import { Pool } from 'pg';
import crypto from 'crypto';
import { als } from './trace.js';

const DATABASE_URL =
  process.env.DATABASE_URL || 'postgres://postgres:12345678@localhost:5432/loopback';

export const pool = new Pool({ connectionString: DATABASE_URL });

/**
 * Execute a tagged query. Appends `/* loopback: trace=... user=... op=... *␁/`
 * and records a db_event on the current trace context for the SOC ingest.
 */
export async function tq(text, params = []) {
  const store = als.getStore();
  let sql = text;
  if (store) {
    const userTag = store.actorId ? ` user=${store.actorId}` : '';
    sql = `${text} /* loopback: trace=${store.traceId}${userTag} op=${store.endpoint || 'n/a'} */`;
  }
  const res = await pool.query(sql, params);
  if (store) {
    store.dbEvents.push({
      kind: 'db',
      ts: new Date().toISOString(),
      traceId: store.traceId,
      actorId: store.actorId ?? null,
      username: store.username ?? null,
      query: text,
      template: text.replace(/\$\d+/g, '?').replace(/\s+/g, ' ').trim().slice(0, 200),
      rowCount: res.rowCount ?? 0,
    });
  }
  return res;
}

export async function ensureSchema() {
  const ddl = [
    `CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      email TEXT,
      password TEXT NOT NULL,
      api_key TEXT UNIQUE NOT NULL,
      address TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS accounts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      account_number TEXT UNIQUE NOT NULL,
      type TEXT NOT NULL DEFAULT 'CHECKING',
      balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'ZWL'
    )`,
    `CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      account_id INTEGER NOT NULL REFERENCES accounts(id),
      from_user_id INTEGER,
      to_account_number TEXT,
      amount NUMERIC(14,2) NOT NULL,
      type TEXT NOT NULL,
      description TEXT,
      balance_after NUMERIC(14,2),
      created_at TIMESTAMPTZ DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT now()
    )`,
  ];
  // Retry while the compose db container finishes booting.
  for (let attempt = 1; attempt <= 25; attempt++) {
    try {
      for (const stmt of ddl) await pool.query(stmt);
      return;
    } catch (err) {
      if (attempt === 25) throw err;
      console.error(`[target/db] schema attempt ${attempt} failed: ${err.message} — retrying`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

/* ==========================================================================
   Seed — every seeded customer opens with a 500 ZWL deposit
   ========================================================================== */

const SEED_USERS = [
  { username: 'Mary',  name: 'Mary Jane',  email: 'mary.jane@apexbank.test',  password: 'peter', address: '14 Samora Machel Avenue, Harare, Zimbabwe' },
  { username: 'John',  name: 'John Doe',   email: 'john.doe@apexbank.test',   password: 'peter', address: '82 Herbert Chitepo Street, Mutare, Zimbabwe' },
  { username: 'Alice', name: 'Alice Smith',email: 'alice.smith@apexbank.test',password: 'peter', address: '45 Joshua Nkomo Street, Bulawayo, Zimbabwe' },
  { username: 'Bob',   name: 'Bob Vance',  email: 'bob.vance@apexbank.test',  password: 'peter', address: '12 Robert Mugabe Way, Gweru, Zimbabwe' },
];

export async function seedIfEmpty() {
  const { rows } = await tq('SELECT COUNT(*)::int AS n FROM users');
  if (rows[0].n > 0) return false;
  for (const u of SEED_USERS) await createUser(u);
  console.log('[target/db] seeded customers:', SEED_USERS.map((u) => u.username).join(', '));
  return true;
}

/* ==========================================================================
   Row helpers
   ========================================================================== */

export async function createUser({ name, username, email, password, address = '' }) {
  const apiKey = `live_sec_key_${crypto.randomBytes(10).toString('hex')}`;
  const { rows } = await tq(
    'INSERT INTO users (username, name, email, password, api_key, address) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [username.trim(), name.trim(), (email || '').trim() || `${username.trim().toLowerCase()}@apexbank.test`, String(password), apiKey, address]
  );
  const user = rows[0];
  const accountNumber = `ACC-${1000 + user.id}`;
  const { rows: accRows } = await tq(
    'INSERT INTO accounts (user_id, account_number, balance, currency) VALUES ($1,$2,$3,$4) RETURNING *',
    [user.id, accountNumber, 500.0, 'ZWL']
  );
  await tq(
    `INSERT INTO transactions (account_id, from_user_id, to_account_number, amount, type, description, balance_after)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [accRows[0].id, user.id, accountNumber, 500.0, 'DEPOSIT', 'Opening deposit', 500.0]
  );
  return { user, account: accRows[0] };
}

export async function getUserByUsername(username) {
  const term = String(username || '').trim().toLowerCase();
  const { rows } = await tq(
    'SELECT * FROM users WHERE LOWER(username) = $1 OR LOWER(name) = $1 LIMIT 1',
    [term]
  );
  return rows[0];
}

export async function getUserById(id) {
  const { rows } = await tq('SELECT * FROM users WHERE id = $1 LIMIT 1', [Number(id)]);
  return rows[0];
}

export async function updateUserEmail(id, email) {
  const { rows } = await tq('UPDATE users SET email = $2 WHERE id = $1 RETURNING *', [Number(id), email]);
  return rows[0];
}

export async function getAccountByNumber(accountNumber) {
  const { rows } = await tq('SELECT * FROM accounts WHERE account_number = $1 LIMIT 1', [
    String(accountNumber || '').trim(),
  ]);
  return rows[0];
}

export async function getAccountByUserId(userId) {
  const { rows } = await tq('SELECT * FROM accounts WHERE user_id = $1 LIMIT 1', [Number(userId)]);
  return rows[0];
}

export async function getTransactions(accountId) {
  const { rows } = await tq(
    'SELECT * FROM transactions WHERE account_id = $1 ORDER BY created_at DESC LIMIT 100',
    [Number(accountId)]
  );
  return rows;
}

export async function createTransaction({ accountId, fromUserId, toAccountNumber, amount, type, description, balanceAfter }) {
  const { rows } = await tq(
    `INSERT INTO transactions (account_id, from_user_id, to_account_number, amount, type, description, balance_after)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [Number(accountId), fromUserId ?? null, toAccountNumber ?? null, Number(amount), type, description ?? null, balanceAfter ?? null]
  );
  return rows[0];
}

export async function debit(accountId, amount) {
  // Intentionally unguarded: negative amounts credit the sender (business-logic flaw).
  const { rows } = await tq(
    'UPDATE accounts SET balance = balance - $2 WHERE id = $1 RETURNING balance',
    [Number(accountId), Number(amount)]
  );
  return Number(rows[0]?.balance ?? 0);
}

export async function credit(accountId, amount) {
  const { rows } = await tq(
    'UPDATE accounts SET balance = balance + $2 WHERE id = $1 RETURNING balance',
    [Number(accountId), Number(amount)]
  );
  return Number(rows[0]?.balance ?? 0);
}

/* ==========================================================================
   Sessions
   ========================================================================== */

export async function createSession(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  await tq('INSERT INTO sessions (token, user_id) VALUES ($1,$2)', [token, Number(userId)]);
  return token;
}

export async function getSessionUser(token) {
  if (!token) return null;
  const { rows } = await tq(
    'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1 LIMIT 1',
    [token]
  );
  return rows[0] || null;
}

export async function deleteSession(token) {
  await tq('DELETE FROM sessions WHERE token = $1', [token]);
}

export function safeUser(user) {
  if (!user) return null;
  const { password, ...rest } = user;
  return rest;
}
