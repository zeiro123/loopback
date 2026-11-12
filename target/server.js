/**
 * Apex Trust Bank — deliberately vulnerable REST + GraphQL banking target.
 *
 * Serves a realistic bank on PostgreSQL (ZWL accounts) and forwards every
 * request (REST + GraphQL) plus its tagged SQL queries to the Loopback SOC.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createYoga, createSchema } from 'graphql-yoga';
import {
  ensureSchema, seedIfEmpty, tq, pool,
  createUser, getUserByUsername, getUserById, updateUserEmail,
  getAccountByNumber, getAccountByUserId, getTransactions,
  createTransaction, debit, credit,
  createSession, getSessionUser, deleteSession, safeUser,
} from './db.js';
import {
  traceMiddleware, als, setActor, setParams, setResourceOwner, setMeta, setOperation,
} from './trace.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 5000);
const BANK_NAME = 'Apex Trust Bank';

const app = express();
app.disable('x-powered-by');
app.use(traceMiddleware);
app.use(express.json());

/* ==========================================================================
   Auth middleware
   ========================================================================== */

app.use(async (req, _res, next) => {
  const header = req.headers['authorization'];
  if (header && header.startsWith('Bearer ')) {
    const token = header.slice(7).trim();
    const user = await getSessionUser(token);
    if (user) {
      req.token = token;
      req.user = user;
      setActor(user, token);
    }
  }
  next();
});

function requireAuth(req, res) {
  if (!req.user) {
    res.status(401).json({ success: false, error: 'Unauthorized: missing or invalid session token' });
    return false;
  }
  return true;
}

/* ==========================================================================
   Statement document builder
   ========================================================================== */

function buildStatementText(statement) {
  const line = '================================================================================';
  const rows = statement.transactions.map((t) => {
    const dt = new Date(t.created_at).toISOString().replace('T', ' ').substring(0, 19);
    const desc = String(t.description || '').padEnd(36).substring(0, 36);
    const amt = `ZWL ${Number(t.amount).toFixed(2)}`.padStart(14);
    return `${dt} | ${String(t.type).padEnd(8)} | ${desc} | ${amt}`;
  });
  return [
    line,
    `                        ${BANK_NAME.toUpperCase()} OF ZIMBABWE`,
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

async function buildStatement(accountNumber) {
  const account = await getAccountByNumber(accountNumber);
  if (!account) return null;
  const owner = await getUserById(account.user_id);
  if (!owner) return null;
  const txns = await getTransactions(account.id);
  const statement = {
    statementId: `STM-2026-${String(account.account_number).replace('ACC-', '')}92`,
    generatedAt: new Date().toISOString(),
    bankName: BANK_NAME,
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
   REST — authentication
   ========================================================================== */

app.post('/api/auth/register', async (req, res) => {
  const { name, username, email, password } = req.body || {};
  setParams({ name, username, email });
  if (!name || !username || !password || String(password).length < 4) {
    return res.status(400).json({
      success: false,
      error: 'Name, username and a password of at least 4 characters are required',
    });
  }
  const existing = await getUserByUsername(username);
  if (existing) {
    return res.status(409).json({ success: false, error: 'That username is already taken' });
  }
  const { user, account } = await createUser({ name, username, email, password });
  const token = await createSession(user.id);
  setResourceOwner({ userId: user.id, accountNumber: account.account_number });
  setMeta({ openedWith: '500 ZWL opening deposit' });
  res.status(201).json({
    success: true,
    message: `Welcome to ${BANK_NAME}, ${user.name}! Your account ${account.account_number} has been opened with a 500 ZWL deposit.`,
    token,
    user: safeUser(user),
    account: {
      accountNumber: account.account_number,
      type: account.type,
      balance: Number(account.balance),
      currency: account.currency,
    },
  });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  setParams({ username });
  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password are required' });
  }
  const user = await getUserByUsername(username);
  if (!user || user.password !== String(password).trim()) {
    return res.status(401).json({ success: false, error: 'Invalid username or password' });
  }
  const token = await createSession(user.id);
  const account = await getAccountByUserId(user.id);
  setMeta({ login: 'success' });
  res.json({
    success: true,
    message: `Welcome back, ${user.name}!`,
    token,
    user: safeUser(user),
    account: account
      ? {
          accountNumber: account.account_number,
          type: account.type,
          balance: Number(account.balance),
          currency: account.currency,
        }
      : null,
  });
});

app.get('/api/auth/me', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const account = await getAccountByUserId(req.user.id);
  res.json({
    success: true,
    user: safeUser(req.user),
    account: account
      ? {
          accountNumber: account.account_number,
          type: account.type,
          balance: Number(account.balance),
          currency: account.currency,
        }
      : null,
  });
});

app.post('/api/auth/logout', async (req, res) => {
  if (req.token) await deleteSession(req.token);
  res.json({ success: true, message: 'Logged out successfully' });
});

/* ==========================================================================
   REST — banking (INTENTIONALLY VULNERABLE)
   ========================================================================== */

// GET /api/accounts/:accountNumber/balance — VULN: no object-level authorization
app.get('/api/accounts/:accountNumber/balance', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const account = await getAccountByNumber(req.params.accountNumber);
  if (!account) return res.status(404).json({ success: false, error: 'Account not found' });
  const owner = await getUserById(account.user_id);
  setResourceOwner({ userId: account.user_id, accountNumber: account.account_number });
  setMeta({ balance: Number(account.balance) });
  res.json({
    success: true,
    accountId: account.id,
    accountNumber: account.account_number,
    accountType: account.type,
    balance: Number(account.balance),
    currency: account.currency,
    ownerName: owner?.name,
    ownerUserId: account.user_id,
  });
});

// GET /api/accounts/:accountNumber/transactions — VULN: no ownership check (IDOR)
app.get('/api/accounts/:accountNumber/transactions', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const account = await getAccountByNumber(req.params.accountNumber);
  if (!account) return res.status(404).json({ success: false, error: 'Account not found' });
  const owner = await getUserById(account.user_id);
  const txns = await getTransactions(account.id);
  setResourceOwner({ userId: account.user_id, accountNumber: account.account_number });
  setMeta({ transactionCount: txns.length });
  res.json({
    success: true,
    accountNumber: account.account_number,
    ownerName: owner?.name,
    ownerUserId: account.user_id,
    transactions: txns,
  });
});

// POST /api/transfers — VULN: negative amounts inflate the balance, overdraft bypassed
app.post('/api/transfers', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const { toAccountNumber, amount, memo } = req.body || {};
  const numAmount = Number(amount);
  setParams({ toAccountNumber, amount: numAmount });

  if (!toAccountNumber || !Number.isFinite(numAmount) || numAmount === 0) {
    return res.status(400).json({ success: false, error: 'Recipient account and a non-zero amount are required' });
  }

  const source = await getAccountByUserId(req.user.id);
  if (!source) return res.status(404).json({ success: false, error: 'Source account not found' });

  const target = await getAccountByNumber(toAccountNumber);
  const balanceBefore = Number(source.balance);

  // LOOPHOLE 1: negative amount → `balance -= (-150)` inflates the sender.
  // LOOPHOLE 2: no insufficient-funds check → overdraft beyond the balance.
  const isNegativeExploit = numAmount < 0;
  const isOverdraftExploit = numAmount > 0 && numAmount > balanceBefore;

  const balanceAfter = await debit(source.id, numAmount);
  await createTransaction({
    accountId: source.id,
    fromUserId: req.user.id,
    toAccountNumber,
    amount: Math.abs(numAmount),
    type: 'TRANSFER',
    description: memo || (isNegativeExploit ? 'Reverse adjustment' : `Transfer to ${toAccountNumber}`),
    balanceAfter,
  });

  if (target) {
    await credit(target.id, numAmount);
    await createTransaction({
      accountId: target.id,
      fromUserId: req.user.id,
      toAccountNumber: target.account_number,
      amount: Math.abs(numAmount),
      type: isNegativeExploit ? 'TRANSFER' : 'DEPOSIT',
      description: isNegativeExploit
        ? `Reversed claim from ${req.user.name} (${source.account_number})`
        : `Received from ${req.user.name} (${source.account_number}): ${memo || 'Transfer'}`,
    });
  }

  setResourceOwner(target ? { userId: target.user_id, accountNumber: target.account_number } : null);
  setMeta({
    amount: numAmount,
    balanceBefore,
    balanceAfter,
    toAccountNumber,
    targetOwnerUserId: target?.user_id ?? null,
    sourceAccountNumber: source.account_number,
  });

  res.json({
    success: true,
    message: isNegativeExploit
      ? `Transfer processed. Balance credited by ZWL ${Math.abs(numAmount).toFixed(2)}.`
      : isOverdraftExploit
      ? `Overdraft transfer approved: ZWL ${numAmount.toFixed(2)} sent.`
      : `Transferred ZWL ${numAmount.toFixed(2)} to ${toAccountNumber}.`,
    updatedBalance: balanceAfter,
  });
});

// GET /api/statements/:accountNumber — VULN: IDOR / BOLA on account number
app.get('/api/statements/:accountNumber', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const requested = String(req.params.accountNumber || '').trim();
  setParams({ accountNumber: requested });
  const built = await buildStatement(requested);
  if (!built) return res.status(404).json({ success: false, error: `Account ${requested} not found` });

  setResourceOwner({ userId: built.statement.accountHolder.userId, accountNumber: requested });
  setMeta({
    ownerName: built.statement.accountHolder.name,
    ownerAddress: built.statement.accountHolder.address,
    balance: built.statement.account.balance,
  });

  res.json({ success: true, statement: built.statement, textDocument: built.textDocument });
});

// PUT /api/users/:id/email — VULN: cross-user modification
app.put('/api/users/:id/email', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const { email } = req.body || {};
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ success: false, error: 'A valid email address is required' });
  }
  const target = await getUserById(req.params.id);
  const updated = await updateUserEmail(req.params.id, email.trim());
  if (!updated) return res.status(404).json({ success: false, error: 'User not found' });
  setResourceOwner({ userId: updated.id });
  setMeta({ changedFrom: target?.email ?? null, changedTo: email.trim() });
  res.json({ success: true, message: `Email updated for user ID ${updated.id}`, user: safeUser(updated) });
});

// GET /api/users/:id/apikey — VULN: cross-user secret key access
app.get('/api/users/:id/apikey', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const target = await getUserById(req.params.id);
  setParams({ targetUserId: Number(req.params.id) });
  if (!target) return res.status(404).json({ success: false, error: 'User does not exist' });
  setResourceOwner({ userId: target.id });
  setMeta({ secret: 'api_key_accessed' });
  res.json({ success: true, userId: target.id, username: target.username, name: target.name, apiKey: target.api_key });
});

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ success: true, status: 'ok', db: 'up' });
  } catch (err) {
    res.status(500).json({ success: false, status: 'degraded', db: 'down', error: err.message });
  }
});

/* ==========================================================================
   GraphQL — same bank, same vulnerabilities, second API surface
   ========================================================================== */

const typeDefs = /* GraphQL */ `
  type User {
    id: Int!
    username: String!
    name: String!
    email: String!
    address: String
    apiKey: String!
  }
  type Account {
    accountNumber: String!
    type: String!
    balance: Float!
    currency: String!
    ownerUserId: Int!
    transactions: [Transaction!]!
  }
  type Transaction {
    id: Int!
    description: String
    amount: Float!
    type: String!
    createdAt: String!
  }
  type Statement {
    accountNumber: String!
    ownerName: String!
    ownerEmail: String!
    address: String!
    balance: Float!
    currency: String!
    statementId: String!
    textDocument: String!
  }
  type TransferResult {
    success: Boolean!
    message: String!
    balance: Float!
  }
  type RegisterResult {
    success: Boolean!
    token: String
    message: String!
  }
  type Query {
    me: User
    user(id: Int!): User
    account(accountNumber: String!): Account
    statement(accountNumber: String!): Statement
  }
  type Mutation {
    transfer(toAccountNumber: String!, amount: Float!, memo: String): TransferResult!
    register(name: String!, username: String!, email: String, password: String!): RegisterResult!
  }
`;

function gqlAuth(ctx) {
  if (!ctx.user) throw new Error('Unauthorized: missing or invalid session token');
  return ctx.user;
}

function gqlUser(user) {
  if (!user) return null;
  const { password, api_key, ...rest } = user;
  return { ...rest, apiKey: api_key ?? null };
}

const resolvers = {
  Query: {
    me: async (_p, _a, ctx) => {
      const user = gqlAuth(ctx);
      setOperation('me');
      return gqlUser(user);
    },
    // VULN: any user's email + secret API key by numeric id (BOLA)
    user: async (_p, { id }, ctx) => {
      gqlAuth(ctx);
      setOperation('user');
      setParams({ targetUserId: id });
      const target = await getUserById(id);
      if (!target) throw new Error(`User ${id} does not exist`);
      setResourceOwner({ userId: target.id });
      setMeta({ secret: 'api_key_accessed' });
      return gqlUser(target);
    },
    // VULN: any account's balance + transactions by account number (IDOR)
    account: async (_p, { accountNumber }, ctx) => {
      gqlAuth(ctx);
      setOperation('account');
      setParams({ accountNumber });
      const account = await getAccountByNumber(accountNumber);
      if (!account) throw new Error(`Account ${accountNumber} not found`);
      const txns = await getTransactions(account.id);
      setResourceOwner({ userId: account.user_id, accountNumber: account.account_number });
      setMeta({ balance: Number(account.balance), transactionCount: txns.length });
      return {
        accountNumber: account.account_number,
        type: account.type,
        balance: Number(account.balance),
        currency: account.currency,
        ownerUserId: account.user_id,
        transactions: txns.map((t) => ({
          id: t.id,
          description: t.description,
          amount: Number(t.amount),
          type: t.type,
          createdAt: new Date(t.created_at).toISOString(),
        })),
      };
    },
    // VULN: any account holder's statement (PII leak)
    statement: async (_p, { accountNumber }, ctx) => {
      gqlAuth(ctx);
      setOperation('statement');
      setParams({ accountNumber });
      const built = await buildStatement(accountNumber);
      if (!built) throw new Error(`Account ${accountNumber} not found`);
      setResourceOwner({ userId: built.statement.accountHolder.userId, accountNumber });
      setMeta({
        ownerName: built.statement.accountHolder.name,
        ownerAddress: built.statement.accountHolder.address,
        balance: built.statement.account.balance,
      });
      return {
        accountNumber: built.statement.account.accountNumber,
        ownerName: built.statement.accountHolder.name,
        ownerEmail: built.statement.accountHolder.email,
        address: built.statement.accountHolder.address,
        balance: built.statement.account.balance,
        currency: built.statement.account.currency,
        statementId: built.statement.statementId,
        textDocument: built.textDocument,
      };
    },
  },
  Mutation: {
    // VULN: identical business-logic flaws over GraphQL
    transfer: async (_p, { toAccountNumber, amount, memo }, ctx) => {
      const user = gqlAuth(ctx);
      setOperation('transfer');
      const numAmount = Number(amount);
      setParams({ toAccountNumber, amount: numAmount });
      if (!toAccountNumber || !Number.isFinite(numAmount) || numAmount === 0) {
        throw new Error('Recipient account and a non-zero amount are required');
      }
      const source = await getAccountByUserId(user.id);
      if (!source) throw new Error('Source account not found');
      const target = await getAccountByNumber(toAccountNumber);
      const balanceBefore = Number(source.balance);
      const isNegativeExploit = numAmount < 0;
      const isOverdraftExploit = numAmount > 0 && numAmount > balanceBefore;

      const balanceAfter = await debit(source.id, numAmount);
      await createTransaction({
        accountId: source.id,
        fromUserId: user.id,
        toAccountNumber,
        amount: Math.abs(numAmount),
        type: 'TRANSFER',
        description: memo || (isNegativeExploit ? 'Reverse adjustment' : `Transfer to ${toAccountNumber}`),
        balanceAfter,
      });
      if (target) {
        await credit(target.id, numAmount);
        await createTransaction({
          accountId: target.id,
          fromUserId: user.id,
          toAccountNumber: target.account_number,
          amount: Math.abs(numAmount),
          type: isNegativeExploit ? 'TRANSFER' : 'DEPOSIT',
          description: isNegativeExploit
            ? `Reversed claim from ${user.name} (${source.account_number})`
            : `Received from ${user.name} (${source.account_number}): ${memo || 'Transfer'}`,
        });
      }
      setResourceOwner(target ? { userId: target.user_id, accountNumber: target.account_number } : null);
      setMeta({
        amount: numAmount,
        balanceBefore,
        balanceAfter,
        toAccountNumber,
        targetOwnerUserId: target?.user_id ?? null,
        sourceAccountNumber: source.account_number,
      });
      return {
        success: true,
        message: isNegativeExploit
          ? `Transfer processed. Balance credited by ZWL ${Math.abs(numAmount).toFixed(2)}.`
          : isOverdraftExploit
          ? `Overdraft transfer approved: ZWL ${numAmount.toFixed(2)} sent.`
          : `Transferred ZWL ${numAmount.toFixed(2)} to ${toAccountNumber}.`,
        balance: balanceAfter,
      };
    },
    register: async (_p, { name, username, email, password }) => {
      setOperation('register');
      setParams({ name, username, email });
      if (!name || !username || !password || String(password).length < 4) {
        throw new Error('Name, username and a password of at least 4 characters are required');
      }
      if (await getUserByUsername(username)) throw new Error('That username is already taken');
      const { user, account } = await createUser({ name, username, email, password });
      const token = await createSession(user.id);
      setResourceOwner({ userId: user.id, accountNumber: account.account_number });
      setMeta({ openedWith: '500 ZWL opening deposit' });
      return {
        success: true,
        token,
        message: `Account ${account.account_number} opened with a 500 ZWL deposit for ${user.name}.`,
      };
    },
  },
};

const yoga = createYoga({
  schema: createSchema({ typeDefs, resolvers }),
  graphqlEndpoint: '/graphql',
  context: ({ req }) => ({ user: req.user ?? null, token: req.token ?? null }),
  maskedErrors: false,
  landingPage: true,
});
app.use('/graphql', yoga);

/* ==========================================================================
   Static bank UI
   ========================================================================== */

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

/* ==========================================================================
   Boot
   ========================================================================== */

async function start() {
  await ensureSchema();
  await seedIfEmpty();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Apex Trust Bank] http://localhost:${PORT}  (GraphQL: /graphql)`);
    console.log(`[Apex Trust Bank] streaming events to Loopback SOC at ${process.env.SOC_URL || 'http://localhost:5100'}`);
  });
}

start().catch((err) => {
  console.error('[Apex Trust Bank] failed to start:', err);
  process.exit(1);
});
