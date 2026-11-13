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
      phone TEXT DEFAULT '',
      occupation TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT now()
    )`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT ''`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS occupation TEXT DEFAULT ''`,
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
    // ---- company blog ----
    `CREATE TABLE IF NOT EXISTS blog_posts (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      excerpt TEXT,
      body TEXT,
      author_name TEXT,
      published_at TIMESTAMPTZ DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS blog_comments (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES blog_posts(id),
      user_id INTEGER,
      author_name TEXT,
      body TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    )`,
    // ---- careers ----
    `CREATE TABLE IF NOT EXISTS jobs (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      department TEXT,
      location TEXT,
      employment_type TEXT,
      description TEXT,
      salary_min NUMERIC(12,2),
      salary_max NUMERIC(12,2),
      open BOOLEAN DEFAULT true,
      posted_at TIMESTAMPTZ DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS job_applications (
      id SERIAL PRIMARY KEY,
      job_id INTEGER NOT NULL REFERENCES jobs(id),
      user_id INTEGER NOT NULL REFERENCES users(id),
      cover_letter TEXT,
      status TEXT DEFAULT 'SUBMITTED',
      created_at TIMESTAMPTZ DEFAULT now()
    )`,
    // ---- support chat ----
    `CREATE TABLE IF NOT EXISTS support_messages (
      id SERIAL PRIMARY KEY,
      convo_id TEXT NOT NULL,
      user_id INTEGER,
      role TEXT NOT NULL,
      text TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    )`,
    // ---- SOC control plane (blocklists / revocations applied by the SOC) ----
    `CREATE TABLE IF NOT EXISTS soc_controls (
      id SERIAL PRIMARY KEY,
      kind TEXT NOT NULL,
      value TEXT NOT NULL,
      reason TEXT,
      source TEXT DEFAULT 'manual',
      active BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT now()
    )`,
    `CREATE INDEX IF NOT EXISTS soc_controls_kind_idx ON soc_controls (kind, value, active)`,
  ];
  for (let attempt = 1; attempt <= 25; attempt++) {
    try {
      for (const stmt of ddl) await pool.query(stmt);
      await seedContent();
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
  { username: 'Mary',    name: 'Mary Jane',        email: 'mary.jane@apexbank.test',    password: 'peter',        address: '14 Samora Machel Avenue, Harare, Zimbabwe',   phone: '+263 771 002 100', occupation: 'Retailer' },
  { username: 'John',    name: 'John Doe',         email: 'john.doe@apexbank.test',     password: 'peter',        address: '82 Herbert Chitepo Street, Mutare, Zimbabwe', phone: '+263 772 003 200', occupation: 'Teacher' },
  { username: 'Alice',   name: 'Alice Smith',      email: 'alice.smith@apexbank.test',  password: 'peter',        address: '45 Joshua Nkomo Street, Bulawayo, Zimbabwe',  phone: '+263 773 004 300', occupation: 'Engineer' },
  { username: 'Bob',     name: 'Bob Vance',        email: 'bob.vance@apexbank.test',    password: 'peter',        address: '12 Robert Mugabe Way, Gweru, Zimbabwe',       phone: '+263 774 005 400', occupation: 'Farmer' },
  { username: 'Tendai',  name: 'Tendai Moyo',      email: 'tendai.moyo@apexbank.test',  password: 'tendai2026',   address: '8 Fife Avenue, Harare, Zimbabwe',             phone: '+263 775 110 011', occupation: 'Accountant' },
  { username: 'Rudo',    name: 'Rudo Chirwa',      email: 'rudo.chirwa@apexbank.test',  password: 'rudo2026',     address: '22 Josiah Tongogara St, Bulawayo, Zimbabwe',  phone: '+263 776 220 022', occupation: 'Nurse' },
  { username: 'Kudzai',  name: 'Kudzai Ncube',     email: 'kudzai.ncube@apexbank.test', password: 'kudzai2026',   address: '3 Leopold Takawira St, Harare, Zimbabwe',     phone: '+263 777 330 033', occupation: 'Software Developer' },
  { username: 'Nyasha',  name: 'Nyasha Gumbo',     email: 'nyasha.gumbo@apexbank.test', password: 'nyasha2026',   address: '17 Robert Mugabe Rd, Kwekwe, Zimbabwe',       phone: '+263 778 440 044', occupation: 'Logistics' },
  { username: 'Chipo',   name: 'Chipo Marange',    email: 'chipo.marange@apexbank.test',password: 'chipo2026',    address: '91 Churchill Ave, Harare, Zimbabwe',          phone: '+263 779 550 055', occupation: 'Lecturer' },
  { username: 'Tapiwa',  name: 'Tapiwa Dube',      email: 'tapiwa.dube@apexbank.test',  password: 'tapiwa2026',   address: '5 Fife Street, Bulawayo, Zimbabwe',           phone: '+263 770 660 066', occupation: 'Mechanic' },
  { username: 'Rutendo', name: 'Rutendo Nyoni',    email: 'rutendo.nyoni@apexbank.test',password: 'rutendo2026',  address: '36 Samora Machel Ave, Harare, Zimbabwe',      phone: '+263 771 770 077', occupation: 'Pharmacist' },
  { username: 'Farai',   name: 'Farai Katsande',   email: 'farai.katsande@apexbank.test',password: 'farai2026',   address: '12 Enterprise Rd, Harare, Zimbabwe',          phone: '+263 772 880 088', occupation: 'Transport' },
  { username: 'Munashe', name: 'Munashe Zvobgo',   email: 'munashe.zvobgo@apexbank.test',password: 'munashe2026', address: '7 Lobengula St, Bulawayo, Zimbabwe',          phone: '+263 773 990 099', occupation: 'Student' },
  { username: 'Shamiso', name: 'Shamiso Mhaka',    email: 'shamiso.mhaka@apexbank.test',password: 'shamiso2026',  address: '48 Bournemouth Rd, Harare, Zimbabwe',         phone: '+263 774 110 110', occupation: 'Journalist' },
  { username: 'Takudzwa',name: 'Takudzwa Siziba',  email: 'takudzwa.siziba@apexbank.test',password: 'takudzwa2026',address: '25 9th Ave, Gweru, Zimbabwe',                 phone: '+263 775 220 220', occupation: 'Electrician' },
  { username: 'Vimbai',  name: 'Vimbai Chingono',  email: 'vimbai.chingono@apexbank.test',password: 'vimbai2026', address: '63 Kwame Nkrumah Ave, Harare, Zimbabwe',      phone: '+263 776 330 330', occupation: 'Designer' },
  { username: 'Anesu',   name: 'Anesu Pfumojena',  email: 'anesu.pfumojena@apexbank.test',password: 'anesu2026',  address: '9 Josiah Chinamano St, Kadoma, Zimbabwe',     phone: '+263 777 440 440', occupation: 'Farmer' },
  { username: 'Tinotenda',name: 'Tinotenda Mapfumo',email: 'tinotenda.mapfumo@apexbank.test',password: 'tinotenda2026',address: '11 Chiremba Rd, Mutare, Zimbabwe',       phone: '+263 778 550 550', occupation: 'Doctor' },
  { username: 'Rejoice', name: 'Rejoice Nyemba',   email: 'rejoice.nyemba@apexbank.test',password: 'rejoice2026',  address: '32 Jason Moyo Ave, Harare, Zimbabwe',         phone: '+263 779 660 660', occupation: 'Broker' },
  { username: 'Panashe', name: 'Panashe Gurajena', email: 'panashe.gurajena@apexbank.test',password: 'panashe2026',address: '6 Connaught Rd, Chinhoyi, Zimbabwe',          phone: '+263 770 770 770', occupation: 'Chef' },
];

// Deterministic pseudo-random so every fresh install seeds the same realistic history
function lcg(seed) {
  let s = seed % 2147483647;
  if (s <= 0) s += 2147483646;
  return () => (s = (s * 48271) % 2147483647) / 2147483647;
}

const SPEND_DESCRIPTIONS = ['OK Zimbabwe', 'Choppies Supermarket', 'TM Pick n Pay', 'Innscor', 'Econet airtime bundle', 'Fuel — Servo Garage', 'ZUPCO monthly fare', 'Pharmacy', 'Hardware supplies'];
const INCOME_DESCRIPTIONS = ['Monthly salary', 'Salary payment', 'Freelance payment', 'Sale proceeds'];

async function generateHistory(user, account, index) {
  const rnd = lcg(1000 + index * 77);
  const count = 3 + Math.floor(rnd() * 4); // 3–6 extra transactions
  const events = [];
  for (let i = 0; i < count; i++) {
    const days = 2 + Math.floor(rnd() * 28);
    const roll = rnd();
    if (roll < 0.45) {
      events.push({ days, type: 'DEPOSIT', amount: Math.round(50 + rnd() * 450), description: INCOME_DESCRIPTIONS[Math.floor(rnd() * INCOME_DESCRIPTIONS.length)] });
    } else {
      events.push({ days, type: 'TRANSFER', amount: Math.round(15 + rnd() * 260), description: SPEND_DESCRIPTIONS[Math.floor(rnd() * SPEND_DESCRIPTIONS.length)] });
    }
  }
  events.sort((a, b) => b.days - a.days); // oldest first
  let running = 500; // opening deposit
  for (const e of events) {
    running += e.type === 'DEPOSIT' ? e.amount : -e.amount;
    await tq(
      `INSERT INTO transactions (account_id, from_user_id, to_account_number, amount, type, description, balance_after, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [account.id, user.id, account.account_number, e.amount, e.type, e.description, running, new Date(Date.now() - e.days * 86400000).toISOString()]
    );
  }
  await tq('UPDATE accounts SET balance = $2 WHERE id = $1', [account.id, running]);
}

const SEED_POSTS = [
  { title: 'Apex Trust Bank launches instant ZWL transfers', slug: 'instant-zwl-transfers', excerpt: 'Move money between client accounts in seconds — no queues, no paperwork.', body: 'Today we are switching on instant internal transfers for all Apex Trust clients. Transfers between client accounts now settle immediately, 24/7, with a full audit trail on every movement.\n\nWhat this means for you: no cut-off times, no batch delays, and a downloadable official statement the moment any transaction lands. Visit the Send Money tab to try it — your first 500 ZWL of fees this month is on us.', author_name: 'Apex Trust Communications' },
  { title: 'Five habits that keep your online banking safe', slug: 'five-safe-banking-habits', excerpt: 'Our security team shares the practical basics that stop most account takeovers.', body: '1. Never reuse your banking password anywhere else.\n2. Check the account number twice before sending — transfers are instant and hard to reverse.\n3. Sign out when you finish, especially on shared devices.\n4. Review your transaction history weekly; report anything you do not recognise immediately.\n5. Keep your registered email and phone up to date in Profile Settings so we can reach you fast.', author_name: 'Apex Trust Security Team' },
  { title: 'We are hiring: engineering and fraud analytics', slug: 'we-are-hiring-2026', excerpt: 'Grow with the team building Zimbabwe-friendly digital banking.', body: 'Apex Trust Bank is expanding its digital teams in Harare and Bulawayo. We are looking for backend engineers, fraud analysts, and support specialists who care about building financial products for the local market.\n\nOpen roles are listed on the Careers tab. Applications are reviewed on a rolling basis — attach a short cover letter telling us what you would build first.', author_name: 'Apex Trust People Team' },
];

const SEED_JOBS = [
  { title: 'Backend Engineer (Node.js)', department: 'Engineering', location: 'Harare', employment_type: 'Full-time', description: 'Build and run the REST and GraphQL services behind Apex Trust online banking. You will own APIs end to end — design, Postgres data modelling, observability, and hardening.', salary_min: 24000, salary_max: 42000 },
  { title: 'Fraud & Threat Analyst', department: 'Security Operations', location: 'Harare', employment_type: 'Full-time', description: 'Work the Loopback SOC floor: triage correlated API-to-database alerts, investigate multi-step attack chains, and tune detection rules with the engineering team.', salary_min: 21000, salary_max: 36000 },
  { title: 'Customer Support Specialist', department: 'Client Services', location: 'Bulawayo', employment_type: 'Full-time', description: 'First line of support for our online banking clients — resolve queries over chat and email, and feed recurring issues back to product.', salary_min: 12000, salary_max: 18000 },
  { title: 'Data Engineer (Payments)', department: 'Engineering', location: 'Remote (ZW)', employment_type: 'Contract', description: 'Model payment event streams, build the analytics pipelines behind our fraud statistics, and keep the warehouse fast and trustworthy.', salary_min: 18000, salary_max: 30000 },
  { title: 'Graduate Rotational Programme 2027', department: 'All departments', location: 'Harare / Bulawayo', employment_type: 'Graduate', description: 'A 12-month rotation across engineering, security operations, and client services for recent computer science and engineering graduates.', salary_min: 9000, salary_max: 14000 },
];

async function seedContent() {
  const { rows: p } = await tq('SELECT COUNT(*)::int AS n FROM blog_posts');
  if (p[0].n === 0) {
    for (const post of SEED_POSTS) {
      await tq(
        'INSERT INTO blog_posts (title, slug, excerpt, body, author_name) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (slug) DO NOTHING',
        [post.title, post.slug, post.excerpt, post.body, post.author_name]
      );
    }
  }
  const { rows: j } = await tq('SELECT COUNT(*)::int AS n FROM jobs');
  if (j[0].n === 0) {
    for (const job of SEED_JOBS) {
      await tq(
        'INSERT INTO jobs (title, department, location, employment_type, description, salary_min, salary_max) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [job.title, job.department, job.location, job.employment_type, job.description, job.salary_min, job.salary_max]
      );
    }
  }
}

export async function seedIfEmpty() {
  const { rows } = await tq('SELECT COUNT(*)::int AS n FROM users');
  if (rows[0].n > 0) return false;
  const created = [];
  for (const u of SEED_USERS) {
    const { user, account } = await createUser(u);
    created.push({ user, account });
  }
  // Realistic varying balances + transaction history for every seeded customer
  for (let i = 0; i < created.length; i++) {
    await generateHistory(created[i].user, created[i].account, i);
  }
  console.log('[target/db] seeded customers:', SEED_USERS.map((u) => u.username).join(', '));
  return true;
}

/* ==========================================================================
   Statement document builder
   ========================================================================== */

export function buildStatementText(statement) {
  const line = '================================================================================';
  const rows = statement.transactions.map((t) => {
    const dt = new Date(t.created_at).toISOString().replace('T', ' ').substring(0, 19);
    const desc = String(t.description || '').padEnd(36).substring(0, 36);
    const amt = `ZWL ${Number(t.amount).toFixed(2)}`.padStart(14);
    return `${dt} | ${String(t.type).padEnd(8)} | ${desc} | ${amt}`;
  });
  return [
    line,
    '                        APEX TRUST BANK OF ZIMBABWE',
    '                  Apex Towers, 102 Jason Moyo Avenue, Harare',
    '                          OFFICIAL ACCOUNT STATEMENT',
    line,
    `Statement ID:   ${statement.statementId}`,
    `Date Generated: ${new Date(statement.generatedAt).toLocaleString()}`,
    `Period:         ${statement.period}`,
    '--------------------------------------------------------------------------------',
    'ACCOUNT HOLDER DETAILS:',
    `  Name:         ${statement.accountHolder.name}`,
    `  Account No:   ${statement.account.accountNumber} (${statement.account.type})`,
    `  Email:        ${statement.accountHolder.email}`,
    `  Address:      ${statement.accountHolder.address}`,
    `  Currency:     ${statement.account.currency}`,
    `  Ledger Balance: ZWL ${Number(statement.account.balance).toFixed(2)}`,
    '--------------------------------------------------------------------------------',
    'TRANSACTION HISTORY:',
    'DATE / TIME           | TYPE     | DESCRIPTION                          | AMOUNT',
    '----------------------+----------+--------------------------------------+--------------',
    ...rows,
    line,
    'This is an official computer-generated statement issued by Apex Trust Bank.',
    line,
  ].join('\n');
}

export async function buildStatement(accountNumber) {
  const account = await getAccountByNumber(accountNumber);
  if (!account) return null;
  const owner = await getUserById(account.user_id);
  if (!owner) return null;
  const txns = await getTransactions(account.id);
  const statement = {
    statementId: `STM-2026-${String(account.account_number).replace('ACC-', '')}92`,
    generatedAt: new Date().toISOString(),
    bankName: 'Apex Trust Bank',
    bankAddress: 'Apex Towers, 102 Jason Moyo Avenue, Harare, Zimbabwe',
    period: 'Current active quarter',
    accountHolder: {
      name: owner.name,
      username: owner.username,
      email: owner.email,
      address: owner.address,
      userId: owner.id,
    },
    account: {
      accountNumber: account.account_number,
      type: account.type,
      balance: Number(account.balance),
      currency: account.currency,
    },
    transactions: txns,
  };
  return { statement, textDocument: buildStatementText(statement) };
}

/* ==========================================================================
   Row helpers
   ========================================================================== */

export async function createUser({ name, username, email, password, address = '', phone = '', occupation = '' }) {
  const apiKey = `live_sec_key_${crypto.randomBytes(10).toString('hex')}`;
  const { rows } = await tq(
    'INSERT INTO users (username, name, email, password, api_key, address, phone, occupation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
    [username.trim(), name.trim(), (email || '').trim() || `${username.trim().toLowerCase()}@apexbank.test`, String(password), apiKey, address, phone, occupation]
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

export async function updateUserDetails(id, { email, phone, address, occupation }) {
  const { rows } = await tq(
    `UPDATE users SET
       email = COALESCE($2, email),
       phone = COALESCE($3, phone),
       address = COALESCE($4, address),
       occupation = COALESCE($5, occupation)
     WHERE id = $1 RETURNING *`,
    [Number(id), email ?? null, phone ?? null, address ?? null, occupation ?? null]
  );
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
   Blog
   ========================================================================== */

export async function listBlogPosts() {
  const { rows } = await tq(
    `SELECT p.*, (SELECT COUNT(*)::int FROM blog_comments c WHERE c.post_id = p.id) AS comment_count
     FROM blog_posts p ORDER BY p.published_at DESC`
  );
  return rows;
}

export async function getBlogPost(id) {
  const { rows } = await tq('SELECT * FROM blog_posts WHERE id = $1 LIMIT 1', [Number(id)]);
  return rows[0];
}

export async function listComments(postId) {
  const { rows } = await tq(
    'SELECT * FROM blog_comments WHERE post_id = $1 ORDER BY created_at DESC LIMIT 100',
    [Number(postId)]
  );
  return rows;
}

export async function addComment({ postId, userId, authorName, body }) {
  const { rows } = await tq(
    'INSERT INTO blog_comments (post_id, user_id, author_name, body) VALUES ($1,$2,$3,$4) RETURNING *',
    [Number(postId), userId ?? null, authorName ?? 'Guest', String(body)]
  );
  return rows[0];
}

/* ==========================================================================
   Careers
   ========================================================================== */

export async function listJobs() {
  const { rows } = await tq(
    `SELECT j.*, (SELECT COUNT(*)::int FROM job_applications a WHERE a.job_id = j.id) AS application_count
     FROM jobs j ORDER BY j.posted_at DESC`
  );
  return rows;
}

export async function getJob(id) {
  const { rows } = await tq('SELECT * FROM jobs WHERE id = $1 LIMIT 1', [Number(id)]);
  return rows[0];
}

export async function searchJobs(q) {
  const term = `%${String(q || '').trim()}%`;
  const { rows } = await tq(
    `SELECT j.*, (SELECT COUNT(*)::int FROM job_applications a WHERE a.job_id = j.id) AS application_count
     FROM jobs j
     WHERE j.title ILIKE $1 OR j.department ILIKE $1 OR j.description ILIKE $1
     ORDER BY j.posted_at DESC`,
    [term]
  );
  return rows;
}

export async function createApplication({ jobId, userId, coverLetter }) {
  const { rows } = await tq(
    'INSERT INTO job_applications (job_id, user_id, cover_letter) VALUES ($1,$2,$3) RETURNING *',
    [Number(jobId), Number(userId), String(coverLetter || '')]
  );
  return rows[0];
}

export async function listApplicationsForUser(userId) {
  const { rows } = await tq(
    `SELECT a.*, j.title AS job_title, j.department, j.location
     FROM job_applications a JOIN jobs j ON j.id = a.job_id
     WHERE a.user_id = $1 ORDER BY a.created_at DESC`,
    [Number(userId)]
  );
  return rows;
}

export async function getApplication(id) {
  // VULN: no ownership filter — any caller can read any application by id.
  const { rows } = await tq(
    `SELECT a.*, j.title AS job_title, u.name AS applicant_name, u.email AS applicant_email
     FROM job_applications a JOIN jobs j ON j.id = a.job_id JOIN users u ON u.id = a.user_id
     WHERE a.id = $1 LIMIT 1`,
    [Number(id)]
  );
  return rows[0];
}

export async function withdrawApplication(id) {
  // VULN: no ownership filter — any caller can withdraw any application by id.
  const { rows } = await tq('DELETE FROM job_applications WHERE id = $1 RETURNING id', [Number(id)]);
  return rows[0];
}

/* ==========================================================================
   Support chat
   ========================================================================== */

export async function saveChat({ convoId, userId, role, text }) {
  const { rows } = await tq(
    'INSERT INTO support_messages (convo_id, user_id, role, text) VALUES ($1,$2,$3,$4) RETURNING *',
    [String(convoId), userId ?? null, role, String(text)]
  );
  return rows[0];
}

export async function listChat(convoId) {
  const { rows } = await tq(
    'SELECT * FROM support_messages WHERE convo_id = $1 ORDER BY created_at ASC LIMIT 200',
    [String(convoId)]
  );
  return rows;
}

/* ==========================================================================
   SOC control plane
   ========================================================================== */

export async function applyControl({ kind, value, reason, source = 'manual' }) {
  const { rows } = await tq(
    'INSERT INTO soc_controls (kind, value, reason, source) VALUES ($1,$2,$3,$4) RETURNING *',
    [String(kind), String(value), reason ?? null, source]
  );
  if (kind === 'block_user') {
    // Kill every live session of the blocked user immediately.
    await tq('DELETE FROM sessions WHERE user_id = $1', [Number(value)]);
  } else if (kind === 'revoke_session') {
    await tq('DELETE FROM sessions WHERE token = $1', [String(value)]);
  }
  return rows[0];
}

export async function deactivateControl(kind, value) {
  const { rows } = await tq(
    'UPDATE soc_controls SET active = false WHERE kind = $1 AND value = $2 AND active = true RETURNING id',
    [String(kind), String(value)]
  );
  return rows.length;
}

export async function isUserBlocked(userId) {
  const { rows } = await tq(
    "SELECT 1 FROM soc_controls WHERE kind = 'block_user' AND value = $1 AND active = true LIMIT 1",
    [String(userId)]
  );
  return rows.length > 0;
}

export async function isSessionRevoked(token) {
  if (!token) return false;
  const { rows } = await tq(
    "SELECT 1 FROM soc_controls WHERE kind = 'revoke_session' AND value = $1 AND active = true LIMIT 1",
    [String(token)]
  );
  return rows.length > 0;
}

export async function activeControls() {
  const { rows } = await tq('SELECT * FROM soc_controls WHERE active = true ORDER BY created_at DESC LIMIT 200');
  return rows;
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
  const { password, api_key, ...rest } = user;
  return rest;
}
