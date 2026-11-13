/**
 * Apex Trust Bank — deliberately vulnerable REST + GraphQL banking target.
 *
 * Serves a realistic bank on PostgreSQL (ZWL accounts) and forwards every
 * request (REST + GraphQL) plus its tagged SQL queries to the Loopback SOC.
 *
 * Intentionally vulnerable: BOLA/IDOR (statements, accounts, users, api keys,
 * job applications), negative/overdraft transfers, chatbot data leak,
 * horizontal enumeration. The SOC can block users / revoke sessions through
 * the control plane — enforcement happens on every request.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { yoga } from './graphql.js';
import {
  ensureSchema, seedIfEmpty, pool,
  createUser, getUserByUsername, getUserById, updateUserEmail, updateUserDetails,
  getAccountByNumber, getAccountByUserId, getTransactions,
  createTransaction, debit, credit, safeUser,
  createSession, getSessionUser, deleteSession,
  listBlogPosts, getBlogPost, listComments, addComment,
  listJobs, getJob, createApplication, listApplicationsForUser, getApplication, withdrawApplication,
  saveChat, listChat,
  isUserBlocked, isSessionRevoked,
} from './db.js';
import { buildStatement } from './db.js';
import {
  traceMiddleware, setActor, setParams, setResourceOwner, setMeta,
} from './trace.js';
import { chatbotRespond } from './chatbot.js';
import { handleControl, handleControlPoll } from './controls.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 5000);
const BANK_NAME = 'Apex Trust Bank';

const app = express();
app.disable('x-powered-by');
app.use(traceMiddleware);
app.use(express.json());

/* ==========================================================================
   Auth middleware — resolves the session, then enforces SOC controls
   ========================================================================== */

app.use(async (req, _res, next) => {
  const header = req.headers['authorization'];
  if (header && header.startsWith('Bearer ')) {
    const token = header.slice(7).trim();
    // Control enforcement 1: SOC-revoked sessions are dead immediately.
    if (await isSessionRevoked(token)) {
      req.revoked = true;
      return next();
    }
    const user = await getSessionUser(token);
    if (user) {
      // Control enforcement 2: SOC-blocked users get nothing.
      if (await isUserBlocked(user.id)) {
        req.blocked = true;
        return next();
      }
      req.token = token;
      req.user = user;
      setActor(user, token);
    }
  }
  next();
});

function guard(req, res) {
  if (req.revoked) {
    res.status(401).json({ success: false, error: 'Session revoked by security operations', code: 'SESSION_REVOKED' });
    return false;
  }
  if (req.blocked) {
    res.status(403).json({ success: false, error: 'Account blocked by security operations. Contact support.', code: 'USER_BLOCKED' });
    return false;
  }
  if (!req.user) {
    res.status(401).json({ success: false, error: 'Unauthorized: missing or invalid session token' });
    return false;
  }
  return true;
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
    account: { accountNumber: account.account_number, type: account.type, balance: Number(account.balance), currency: account.currency },
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
  // Control enforcement 3: SOC-blocked users cannot sign in.
  if (await isUserBlocked(user.id)) {
    setMeta({ login: 'blocked' });
    return res.status(403).json({ success: false, error: 'Account blocked by security operations. Contact support.', code: 'USER_BLOCKED' });
  }
  const token = await createSession(user.id);
  const account = await getAccountByUserId(user.id);
  setMeta({ login: 'success' });
  res.json({
    success: true,
    message: `Welcome back, ${user.name}!`,
    token,
    user: safeUser(user),
    account: account ? { accountNumber: account.account_number, type: account.type, balance: Number(account.balance), currency: account.currency } : null,
  });
});

app.get('/api/auth/me', async (req, res) => {
  if (!guard(req, res)) return;
  const account = await getAccountByUserId(req.user.id);
  res.json({
    success: true,
    user: safeUser(req.user),
    account: account ? { accountNumber: account.account_number, type: account.type, balance: Number(account.balance), currency: account.currency } : null,
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
  if (!guard(req, res)) return;
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
  if (!guard(req, res)) return;
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
  if (!guard(req, res)) return;
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
  if (!guard(req, res)) return;
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
  if (!guard(req, res)) return;
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

// GET /api/users/:id — VULN: view any client's full details (PII leak)
app.get('/api/users/:id', async (req, res) => {
  if (!guard(req, res)) return;
  const target = await getUserById(req.params.id);
  setParams({ targetUserId: Number(req.params.id) });
  if (!target) return res.status(404).json({ success: false, error: 'User not found' });
  setResourceOwner({ userId: target.id });
  setMeta({ pii: 'details_viewed' });
  res.json({ success: true, user: safeUser(target) });
});

// PUT /api/users/:id/details — VULN: update any client's details (IDOR write)
app.put('/api/users/:id/details', async (req, res) => {
  if (!guard(req, res)) return;
  const { email, phone, address, occupation } = req.body || {};
  const before = await getUserById(req.params.id);
  const updated = await updateUserDetails(req.params.id, { email, phone, address, occupation });
  if (!updated) return res.status(404).json({ success: false, error: 'User not found' });
  setResourceOwner({ userId: updated.id });
  setMeta({ pii: 'details_modified', changedFrom: { phone: before?.phone, address: before?.address } });
  res.json({ success: true, message: `Details updated for user ID ${updated.id}`, user: safeUser(updated) });
});

// GET /api/users/:id/apikey — VULN: cross-user secret key access
app.get('/api/users/:id/apikey', async (req, res) => {
  if (!guard(req, res)) return;
  const target = await getUserById(req.params.id);
  setParams({ targetUserId: Number(req.params.id) });
  if (!target) return res.status(404).json({ success: false, error: 'User does not exist' });
  setResourceOwner({ userId: target.id });
  setMeta({ secret: 'api_key_accessed' });
  res.json({ success: true, userId: target.id, username: target.username, name: target.name, apiKey: target.api_key });
});

/* ==========================================================================
   REST — company blog
   ========================================================================== */

app.get('/api/blog/posts', async (_req, res) => {
  const posts = await listBlogPosts();
  res.json({ success: true, count: posts.length, posts });
});

app.get('/api/blog/posts/:id', async (req, res) => {
  setParams({ postId: Number(req.params.id) });
  const post = await getBlogPost(req.params.id);
  if (!post) return res.status(404).json({ success: false, error: 'Post not found' });
  const comments = await listComments(post.id);
  res.json({ success: true, post, comments });
});

app.post('/api/blog/posts/:id/comments', async (req, res) => {
  const { body } = req.body || {};
  setParams({ postId: Number(req.params.id) });
  if (!body || !String(body).trim()) {
    return res.status(400).json({ success: false, error: 'Comment body is required' });
  }
  const post = await getBlogPost(req.params.id);
  if (!post) return res.status(404).json({ success: false, error: 'Post not found' });
  const comment = await addComment({
    postId: post.id,
    userId: req.user?.id ?? null,
    authorName: req.user?.name ?? 'Guest',
    body: String(body),
  });
  setResourceOwner(req.user ? { userId: req.user.id } : null);
  res.status(201).json({ success: true, comment });
});

/* ==========================================================================
   REST — careers
   ========================================================================== */

app.get('/api/jobs', async (_req, res) => {
  const jobs = await listJobs();
  res.json({ success: true, count: jobs.length, jobs });
});

app.get('/api/jobs/:id', async (req, res) => {
  const job = await getJob(req.params.id);
  if (!job) return res.status(404).json({ success: false, error: 'Job not found' });
  res.json({ success: true, job });
});

// POST /api/jobs/:id/apply — submit an application (authenticated)
app.post('/api/jobs/:id/apply', async (req, res) => {
  if (!guard(req, res)) return;
  const { coverLetter } = req.body || {};
  const job = await getJob(req.params.id);
  if (!job) return res.status(404).json({ success: false, error: 'Job not found' });
  setParams({ jobId: job.id });
  const app1 = await createApplication({ jobId: job.id, userId: req.user.id, coverLetter });
  const full = await getApplication(app1.id);
  setResourceOwner({ userId: req.user.id });
  setMeta({ jobTitle: job.title });
  res.status(201).json({ success: true, message: `Application submitted for ${job.title}.`, application: full });
});

// GET /api/applications/mine — the signed-in user's applications
app.get('/api/applications/mine', async (req, res) => {
  if (!guard(req, res)) return;
  const apps = await listApplicationsForUser(req.user.id);
  res.json({ success: true, count: apps.length, applications: apps });
});

// GET /api/applications/:id — VULN: any applicant's cover letter + PII (IDOR)
app.get('/api/applications/:id', async (req, res) => {
  if (!guard(req, res)) return;
  setParams({ applicationId: Number(req.params.id) });
  const app1 = await getApplication(req.params.id);
  if (!app1) return res.status(404).json({ success: false, error: 'Application not found' });
  setResourceOwner({ userId: app1.user_id });
  setMeta({ secret: 'job_application_accessed', applicantEmail: app1.applicant_email });
  res.json({ success: true, application: app1 });
});

// DELETE /api/applications/:id — VULN: withdraw ANY applicant's application (IDOR write)
app.delete('/api/applications/:id', async (req, res) => {
  if (!guard(req, res)) return;
  setParams({ applicationId: Number(req.params.id) });
  const app1 = await getApplication(req.params.id);
  if (!app1) return res.status(404).json({ success: false, error: 'Application not found' });
  await withdrawApplication(req.params.id);
  setResourceOwner({ userId: app1.user_id });
  setMeta({ pii: 'application_withdrawn', applicantEmail: app1.applicant_email });
  res.json({ success: true, message: `Application ${req.params.id} withdrawn` });
});

/* ==========================================================================
   REST — support chatbot
   ========================================================================== */

app.post('/api/support/chat', async (req, res) => {
  const { message, convoId } = req.body || {};
  setParams({ message });
  const cid = convoId || `convo_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
  const user = req.user ? safeUser(req.user) : null;
  const account = req.user ? await getAccountByUserId(req.user.id) : null;

  await saveChat({ convoId: cid, userId: req.user?.id ?? null, role: 'user', text: message });
  const reply = await chatbotRespond(message, {
    user,
    account,
    lookupAccount: (num) => getAccountByNumber(num), // VULN: reads any account balance
  });
  await saveChat({ convoId: cid, userId: req.user?.id ?? null, role: 'bot', text: reply });

  res.json({ success: true, convoId: cid, reply });
});

app.get('/api/support/chat/:convoId', async (req, res) => {
  const messages = await listChat(req.params.convoId);
  res.json({ success: true, convoId: req.params.convoId, messages });
});

/* ==========================================================================
   SOC control plane — the Loopback SOC applies response actions here
   ========================================================================== */

app.post('/api/soc/controls', handleControl);
app.get('/api/soc/controls/poll', handleControlPoll);

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ success: true, status: 'ok', db: 'up' });
  } catch (err) {
    res.status(500).json({ success: false, status: 'degraded', db: 'down', error: err.message });
  }
});

/* ==========================================================================
   GraphQL + static bank UI
   ========================================================================== */

app.use('/graphql', yoga);
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
