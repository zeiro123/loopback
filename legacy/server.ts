/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { db, User, SecurityAlert } from './server/db.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

function getPort(): number {
  const portArgIndex = process.argv.indexOf('--port');
  if (portArgIndex !== -1 && process.argv[portArgIndex + 1]) {
    const parsed = parseInt(process.argv[portArgIndex + 1], 10);
    if (!isNaN(parsed) && parsed > 0) return parsed;
  }
  if (process.env.PORT) {
    const parsed = parseInt(process.env.PORT, 10);
    if (!isNaN(parsed) && parsed > 0) return parsed;
  }
  return 3000;
}

const PORT = getPort();

app.use(express.json());

// Extend Express Request
declare global {
  namespace Express {
    interface Request {
      user?: User | null;
      token?: string;
      isSocAdmin?: boolean;
    }
  }
}

// Authentication Middleware: extracts Bearer token
app.use((req: Request, _res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    const session = db.getSession(token);
    if (session) {
      req.token = token;
      if (session.role === 'admin') {
        req.isSocAdmin = true;
      }
      req.user = db.getUserById(session.userId) || null;
    }
  }
  next();
});

// Helper for Gemini AI Explanation (with graceful offline fallback)
async function explainWithGemini(alert: SecurityAlert): Promise<SecurityAlert['explanation']> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return alert.explanation; // Return existing predefined rule
  }

  try {
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: { 'User-Agent': 'aistudio-build' },
      },
    });

    const prompt = `You are a Principal SOC Analyst and API Security Expert.
Analyze this API security alert and explain it clearly:
- Alert Type: ${alert.alertType}
- Severity: ${alert.severity}
- Title: ${alert.title}
- Summary: ${alert.summary}
- User: ${alert.username} (ID: ${alert.userId})
- Endpoint: ${alert.method} ${alert.endpoint} (HTTP Status: ${alert.statusCode})
- Attempts: ${alert.attemptsCount}
- Cross-Functional Lateral Movement: ${alert.isCrossFunctional}

Return a valid JSON object matching these exact keys:
{
  "overview": "Clear 2-3 sentence overview of what the user did and whether it succeeded",
  "rootCause": "Why the backend endpoint permitted this attack to occur",
  "attackMechanics": "Step by step description of how the request parameters were manipulated",
  "businessImpact": "The risk to the organization, financial damage, or regulatory liability",
  "remediation": "Exact code or configuration fix to remediate the vulnerability"
}
Return only JSON.`;

    const res = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        temperature: 0.2,
      },
    });

    const text = res.text?.trim() || '';
    const parsed = JSON.parse(text);
    return {
      source: 'AI_GEMINI',
      overview: parsed.overview || alert.summary,
      rootCause: parsed.rootCause || 'Missing authorization check on requested object identifier.',
      attackMechanics: parsed.attackMechanics || 'User altered target parameter in request.',
      businessImpact: parsed.businessImpact || 'Unauthorized data exposure or financial alteration.',
      remediation: parsed.remediation || 'Enforce session ownership validation on target resource.',
      generatedAt: new Date().toISOString(),
    };
  } catch (err) {
    console.error('Gemini explanation error, using predefined rule fallback:', err);
    return alert.explanation;
  }
}

/* ==========================================================================
   BANKING AUTHENTICATION APIS (Mary / John)
   ========================================================================== */

// POST /api/auth/login
app.post('/api/auth/login', (req: Request, res: Response) => {
  const { username, password } = req.body;
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

  if (!username || !password) {
    db.logAudit({
      userId: null,
      username: String(username || 'Anonymous'),
      sessionToken: null,
      action: 'LOGIN_FAILED',
      narrative: `Login attempt rejected: Missing username or password`,
      method: 'POST',
      endpoint: '/api/auth/login',
      statusCode: 400,
      ipAddress: ip,
    });
    return res.status(400).json({
      success: false,
      error: 'Username and password are required',
    });
  }

  const user = db.getUserByUsername(String(username));

  if (!user || user.password !== String(password).trim()) {
    db.logAudit({
      userId: user ? user.id : null,
      username: String(username),
      sessionToken: null,
      action: 'LOGIN_FAILED',
      narrative: `Failed login attempt for username '${username}'`,
      method: 'POST',
      endpoint: '/api/auth/login',
      statusCode: 401,
      ipAddress: ip,
    });
    return res.status(401).json({
      success: false,
      error: 'Invalid username or password',
    });
  }

  const session = db.createSession(user.id, 'customer');
  const account = db.getAccountByUserId(user.id);

  db.logAudit({
    userId: user.id,
    username: user.username,
    sessionToken: session.token,
    action: 'LOGIN_SUCCESS',
    narrative: `${user.username} logged in`,
    method: 'POST',
    endpoint: '/api/auth/login',
    statusCode: 200,
    ipAddress: ip,
  });

  const { password: _, ...safeUser } = user;

  res.status(200).json({
    success: true,
    message: `Welcome back, ${user.name}!`,
    token: session.token,
    user: safeUser,
    account,
  });
});

// GET /api/auth/me
app.get('/api/auth/me', (req: Request, res: Response) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized: missing or invalid session token',
    });
  }

  const account = db.getAccountByUserId(req.user.id);
  const { password: _, ...safeUser } = req.user;

  res.status(200).json({
    success: true,
    user: safeUser,
    account,
  });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req: Request, res: Response) => {
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  if (req.user) {
    db.logAudit({
      userId: req.user.id,
      username: req.user.username,
      sessionToken: req.token || null,
      action: 'LOGOUT',
      narrative: `${req.user.username} logged out`,
      method: 'POST',
      endpoint: '/api/auth/logout',
      statusCode: 200,
      ipAddress: ip,
    });
  }
  if (req.token) {
    db.deleteSession(req.token);
  }
  res.status(200).json({
    success: true,
    message: 'Logged out successfully',
  });
});

/* ==========================================================================
   SOC OPERATOR AUTHENTICATION (admin / admin)
   ========================================================================== */

// POST /api/soc/login
app.post('/api/soc/login', (req: Request, res: Response) => {
  const { username, password } = req.body;
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';

  if (username === 'admin' && password === 'admin') {
    const session = db.createSession(999, 'admin');
    db.logAudit({
      userId: 999,
      username: 'admin',
      sessionToken: session.token,
      action: 'SOC_ADMIN_LOGIN',
      narrative: `admin logged into SOC console`,
      method: 'POST',
      endpoint: '/api/soc/login',
      statusCode: 200,
      ipAddress: ip,
    });

    return res.status(200).json({
      success: true,
      message: 'SOC Analyst authenticated successfully',
      token: session.token,
      role: 'admin',
    });
  }

  res.status(401).json({
    success: false,
    error: 'Invalid SOC administrative credentials',
  });
});

// GET /api/soc/me
app.get('/api/soc/me', (req: Request, res: Response) => {
  if (!req.isSocAdmin) {
    return res.status(401).json({ success: false, error: 'Unauthorized SOC session' });
  }
  res.status(200).json({ success: true, role: 'admin', username: 'admin' });
});

/* ==========================================================================
   BANKING APIS & INTENTIONAL BUSINESS LOGIC / IDOR VULNERABILITIES
   ========================================================================== */

// GET /api/accounts/:id/balance
app.get('/api/accounts/:id/balance', (req: Request, res: Response) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const idParam = req.params.id;
  let account = db.getAccountById(idParam);
  if (!account && !isNaN(Number(idParam))) {
    account = db.getAccountByUserId(Number(idParam));
  }

  if (!account) {
    return res.status(404).json({ error: 'Account not found' });
  }

  const owner = db.getUserById(account.userId);

  res.status(200).json({
    accountId: account.id,
    accountNumber: account.accountNumber,
    accountType: account.type,
    balance: account.balance,
    currency: account.currency,
    ownerUsername: owner?.username,
    ownerName: owner?.name,
    ownerUserId: account.userId,
  });
});

// GET /api/accounts/:id/transactions
app.get('/api/accounts/:id/transactions', (req: Request, res: Response) => {
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const idParam = req.params.id;
  let account = db.getAccountById(idParam);
  if (!account && !isNaN(Number(idParam))) {
    account = db.getAccountByUserId(Number(idParam));
  }

  if (!account) {
    return res.status(404).json({ error: 'Account not found' });
  }

  const txns = db.getTransactions(account.id);
  const owner = db.getUserById(account.userId);

  // Correlation audit entry
  const isCrossAccount = req.user.id !== account.userId;
  db.logAudit({
    userId: req.user.id,
    username: req.user.username,
    sessionToken: req.token || null,
    action: isCrossAccount ? 'VIEW_TRANSACTIONS_CROSS' : 'VIEW_TRANSACTIONS',
    narrative: isCrossAccount
      ? `${req.user.username} viewed transactions for Account ${account.accountNumber} (${owner?.name || 'User ' + account.userId})`
      : `${req.user.username} viewed account transactions`,
    method: 'GET',
    endpoint: `/api/accounts/${idParam}/transactions`,
    statusCode: 200,
    ipAddress: ip,
  });

  // Raise alert if cross-account access occurs
  if (isCrossAccount) {
    db.createOrUpdateAlert({
      alertType: 'POSSIBLE_IDOR_ATTACK',
      title: 'Possible IDOR Attack: Cross-Account Ledger Access',
      summary: `${req.user.username} (User ${req.user.id}) accessed transaction history of Account ${account.accountNumber} owned by ${owner?.name || 'User ' + account.userId}.`,
      userId: req.user.id,
      username: req.user.username,
      endpoint: `/api/accounts/${idParam}/transactions`,
      method: 'GET',
      statusCode: 200,
      targetUser: owner,
      targetAccount: account,
    });
  }

  res.status(200).json({
    accountId: account.id,
    accountNumber: account.accountNumber,
    ownerUserId: account.userId,
    ownerName: owner?.name,
    transactions: txns,
  });
});

// GET /api/statements/download/:accountNumber
// INTENTIONALLY VULNERABLE TO IDOR / BOLA ON ACCOUNT NUMBER
app.get('/api/statements/download/:accountNumber', (req: Request, res: Response) => {
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Unauthorized: Missing session token' });
  }

  const requestedAccNum = req.params.accountNumber?.trim();
  const statement = db.getStatement(requestedAccNum);

  if (!statement) {
    db.logAudit({
      userId: req.user.id,
      username: req.user.username,
      sessionToken: req.token || null,
      action: 'STATEMENT_PROBE_404',
      narrative: `${req.user.username} requested statement for non-existent Account ${requestedAccNum} (Not Found)`,
      method: 'GET',
      endpoint: `/api/statements/download/${requestedAccNum}`,
      statusCode: 404,
      ipAddress: ip,
    });

    db.createOrUpdateAlert({
      alertType: 'POSSIBLE_IDOR_ATTACK',
      title: 'Possible IDOR Attack: Failed Statement Account Probe',
      summary: `${req.user.username} (User ${req.user.id}) probed bank statement for non-existent Account Number ${requestedAccNum}.`,
      userId: req.user.id,
      username: req.user.username,
      endpoint: `/api/statements/download/${requestedAccNum}`,
      method: 'GET',
      statusCode: 404,
    });

    return res.status(404).json({ success: false, error: `Account ${requestedAccNum} not found` });
  }

  const ownAccount = db.getAccountByUserId(req.user.id);
  const isCrossAccount = ownAccount?.accountNumber !== statement.account.accountNumber;
  const ownerUser = db.getUserById(statement.accountHolder.userId);
  const targetAccount = db.getAccountByNumber(statement.account.accountNumber);

  if (isCrossAccount) {
    // Track sliding window enumeration on statements
    const enumStatus = db.trackEnumeration(req.user.username, requestedAccNum, '/api/statements/download');

    db.logAudit({
      userId: req.user.id,
      username: req.user.username,
      sessionToken: req.token || null,
      action: 'STATEMENT_CROSS_DOWNLOAD',
      narrative: `${req.user.username} downloaded official statement for Account ${requestedAccNum} (${statement.accountHolder.name}, ${statement.accountHolder.address})`,
      method: 'GET',
      endpoint: `/api/statements/download/${requestedAccNum}`,
      statusCode: 200,
      ipAddress: ip,
      metadata: {
        victimAccount: requestedAccNum,
        victimName: statement.accountHolder.name,
        victimAddress: statement.accountHolder.address,
      },
    });

    if (enumStatus.isEnumeration) {
      db.createOrUpdateAlert({
        alertType: 'RESOURCE_ENUMERATION_ATTACK',
        title: 'Automated Account Statement Enumeration Sweep',
        summary: `${req.user.username} rapidly enumerated statements across ${enumStatus.count} unique accounts (${enumStatus.targets.join(', ')}).`,
        userId: req.user.id,
        username: req.user.username,
        endpoint: `/api/statements/download/${requestedAccNum}`,
        method: 'GET',
        statusCode: 200,
        targetAccount: targetAccount || null,
        targetUser: ownerUser || null,
      });
    } else {
      db.createOrUpdateAlert({
        alertType: 'POSSIBLE_IDOR_ATTACK',
        title: 'Possible IDOR Attack: Unauthorized Bank Statement Exfiltration',
        summary: `${req.user.username} (Account ${ownAccount?.accountNumber}) downloaded confidential bank statement for Account ${requestedAccNum} belonging to ${statement.accountHolder.name} (${statement.accountHolder.address}).`,
        userId: req.user.id,
        username: req.user.username,
        endpoint: `/api/statements/download/${requestedAccNum}`,
        method: 'GET',
        statusCode: 200,
        targetAccount: targetAccount || null,
        targetUser: ownerUser || null,
        exploitDetails: `Swapped ${ownAccount?.accountNumber} -> ${requestedAccNum}`,
      });
    }
  } else {
    // Normal legitimate download of own statement
    db.logAudit({
      userId: req.user.id,
      username: req.user.username,
      sessionToken: req.token || null,
      action: 'STATEMENT_DOWNLOAD',
      narrative: `${req.user.username} downloaded official bank statement for Account ${requestedAccNum}`,
      method: 'GET',
      endpoint: `/api/statements/download/${requestedAccNum}`,
      statusCode: 200,
      ipAddress: ip,
    });
  }

  // Format as plain-text document for clean file download
  const textDocument = [
    '================================================================================',
    '                        APEX COMMERCIAL BANK OF ZIMBABWE                        ',
    '                  Apex Towers, 102 Jason Moyo Avenue, Harare                    ',
    '                          OFFICIAL ACCOUNT STATEMENT                            ',
    '================================================================================',
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
    `  Ledger Balance: $${statement.account.balance.toFixed(2)}`,
    '--------------------------------------------------------------------------------',
    'TRANSACTION HISTORY:',
    'DATE / TIME            | TYPE     | DESCRIPTION                          | AMOUNT   ',
    '-----------------------+----------+--------------------------------------+----------',
    ...statement.transactions.map((t: any) => {
      const dt = new Date(t.timestamp).toISOString().replace('T', ' ').substring(0, 19);
      const desc = t.description.padEnd(36).substring(0, 36);
      const amt = `$${t.amount.toFixed(2)}`.padStart(8);
      return `${dt} | ${t.type.padEnd(8)} | ${desc} | ${amt}`;
    }),
    '================================================================================',
    'This is an official computer-generated statement issued by Apex Commercial Bank.',
    '================================================================================',
  ].join('\\n');

  res.status(200).json({
    success: true,
    statement,
    textDocument,
  });
});

// POST /api/transfers
app.post('/api/transfers', (req: Request, res: Response) => {
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { toAccountNumber, amount, description } = req.body;
  const numAmount = parseFloat(amount);

  if (isNaN(numAmount) || numAmount === 0) {
    db.logAudit({
      userId: req.user.id,
      username: req.user.username,
      sessionToken: req.token || null,
      action: 'INVALID_TRANSFER',
      narrative: `${req.user.username} entered invalid transfer amount: ${amount}`,
      method: 'POST',
      endpoint: '/api/transfers',
      statusCode: 400,
      ipAddress: ip,
    });
    return res.status(400).json({ error: 'Invalid transfer amount' });
  }

  const sourceAccount = db.getAccountByUserId(req.user.id);
  if (!sourceAccount) {
    return res.status(404).json({ error: 'Source account not found' });
  }

  const senderUser = db.getUserById(req.user.id);
  const targetAccount = db.getAccountByNumber(toAccountNumber);
  const targetUser = targetAccount ? db.getUserById(targetAccount.userId) : null;

  // LOOPHOLE 1: Negative Amount Exploit
  const isNegativeExploit = numAmount < 0;

  // LOOPHOLE 2: Overdraft Exploit
  const isOverdraftExploit = numAmount > 0 && numAmount > sourceAccount.balance;

  // Execute debit & credit
  sourceAccount.balance -= numAmount;

  // Sender transaction record
  const txn = db.createTransaction({
    accountId: sourceAccount.id,
    fromUserId: req.user.id,
    toAccountNumber,
    amount: Math.abs(numAmount),
    type: 'TRANSFER',
    description: description || (isNegativeExploit ? `Reverse ATM Adjustment` : `Transfer to ${toAccountNumber}`),
  });

  // Credit recipient if exists & record reciprocal transaction
  if (targetAccount) {
    targetAccount.balance += numAmount;
    db.createTransaction({
      accountId: targetAccount.id,
      fromUserId: req.user.id,
      toAccountNumber: targetAccount.accountNumber,
      amount: Math.abs(numAmount),
      type: isNegativeExploit ? 'TRANSFER' : 'DEPOSIT',
      description: isNegativeExploit
        ? `Reversed claim from ${senderUser?.name} (${sourceAccount.accountNumber}): -$${Math.abs(numAmount).toFixed(2)}`
        : `Received from ${senderUser?.name} (${sourceAccount.accountNumber}): ${description || 'Transfer'}`,
    });
  }

  // Simple old-school audit log entry
  const displayTarget = targetUser ? `${targetUser.name}` : toAccountNumber;
  db.logAudit({
    userId: req.user.id,
    username: req.user.username,
    sessionToken: req.token || null,
    action: isNegativeExploit ? 'TRANSFER_NEGATIVE' : isOverdraftExploit ? 'TRANSFER_OVERDRAFT' : 'TRANSFER_SENT',
    narrative: `${req.user.username} sent ${numAmount} to ${toAccountNumber} (${displayTarget})`,
    method: 'POST',
    endpoint: '/api/transfers',
    statusCode: 200,
    ipAddress: ip,
  });

  // Trigger Anomaly Alerts for Business Logic
  if (isNegativeExploit) {
    db.createOrUpdateAlert({
      alertType: 'POSSIBLE_BUSINESS_LOGIC_ATTACK',
      title: 'Possible Business Logic Attack: Negative Amount Balance Inflation',
      summary: `${req.user.username} initiated a negative transfer of $${numAmount.toFixed(2)} to ${toAccountNumber}. Sender balance increased to $${sourceAccount.balance.toFixed(2)}.`,
      userId: req.user.id,
      username: req.user.username,
      endpoint: '/api/transfers',
      method: 'POST',
      statusCode: 200,
      targetAccount,
      targetUser,
      exploitDetails: `amount: ${numAmount}`,
    });
  } else if (isOverdraftExploit) {
    db.createOrUpdateAlert({
      alertType: 'POSSIBLE_BUSINESS_LOGIC_ATTACK',
      title: 'Possible Business Logic Attack: Overdraft Invariant Bypass',
      summary: `${req.user.username} transferred $${numAmount.toFixed(2)} exceeding account balance ($${(sourceAccount.balance + numAmount).toFixed(2)}). Account overdrawn to $${sourceAccount.balance.toFixed(2)}.`,
      userId: req.user.id,
      username: req.user.username,
      endpoint: '/api/transfers',
      method: 'POST',
      statusCode: 200,
      targetAccount,
      targetUser,
      exploitDetails: `transfer amount $${numAmount} on balance $${sourceAccount.balance + numAmount}`,
    });
  }

  res.status(200).json({
    success: true,
    message: isNegativeExploit
      ? `Negative transfer processed: Balance credited by $${Math.abs(numAmount).toFixed(2)}`
      : isOverdraftExploit
      ? `Overdraft transfer approved: $${numAmount.toFixed(2)} sent (Balance now: $${sourceAccount.balance.toFixed(2)})`
      : `Transferred $${numAmount.toFixed(2)} to ${toAccountNumber}`,
    updatedBalance: sourceAccount.balance,
    transaction: txn,
  });
});

// GET /api/users/:id/apikey
// INTENTIONALLY VULNERABLE TO IDOR & ENUMERATION
app.get('/api/users/:id/apikey', (req: Request, res: Response) => {
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Unauthorized: Missing session token' });
  }

  const targetId = Number(req.params.id);
  const targetUser = db.getUserById(targetId);

  if (!targetUser) {
    db.logAudit({
      userId: req.user.id,
      username: req.user.username,
      sessionToken: req.token || null,
      action: 'APIKEY_PROBE_404',
      narrative: `${req.user.username} requested API key for User ID ${targetId} (Not Found)`,
      method: 'GET',
      endpoint: `/api/users/${targetId}/apikey`,
      statusCode: 404,
      ipAddress: ip,
    });

    // Alert: User changed identifier to non-existent ID (failed probe = low severity, unless repeated)
    db.createOrUpdateAlert({
      alertType: 'POSSIBLE_IDOR_ATTACK',
      title: 'Possible IDOR Attack: Failed Identifier Probe',
      summary: `${req.user.username} (User ${req.user.id}) probed API key for non-existent User ID ${targetId}.`,
      userId: req.user.id,
      username: req.user.username,
      endpoint: `/api/users/${targetId}/apikey`,
      method: 'GET',
      statusCode: 404,
    });

    return res.status(404).json({ success: false, error: 'User does not exist' });
  }

  const isCrossUser = req.user.id !== targetUser.id;

  if (isCrossUser) {
    // Audit log
    db.logAudit({
      userId: req.user.id,
      username: req.user.username,
      sessionToken: req.token || null,
      action: 'APIKEY_CROSS_ACCESS',
      narrative: `${req.user.username} requested API key for User ID ${targetId} (${targetUser.name})`,
      method: 'GET',
      endpoint: `/api/users/${targetId}/apikey`,
      statusCode: 200,
      ipAddress: ip,
    });

    // Check sliding window enumeration across IDs
    const trackerKey = `${req.user.id}_${ip}`;
    const enumCheck = db.trackEnumeration(trackerKey, targetId, `/api/users/:id/apikey`);

    if (enumCheck.isEnumeration) {
      db.createOrUpdateAlert({
        alertType: 'RESOURCE_ENUMERATION_ATTACK',
        title: 'Resource Enumeration: Horizontal Fuzzing Sweep',
        summary: `${req.user.username} sequentially probed ${enumCheck.count} distinct user API Keys (Targets: [${enumCheck.targets.join(', ')}]). Horizontal fuzzing attack detected.`,
        userId: req.user.id,
        username: req.user.username,
        endpoint: `/api/users/${targetId}/apikey`,
        method: 'GET',
        statusCode: 200,
        targetUser,
      });
    } else {
      // Single/Repeat IDOR Alert
      db.createOrUpdateAlert({
        alertType: 'POSSIBLE_IDOR_ATTACK',
        title: 'Possible IDOR Attack: Cross-User API Key Access',
        summary: `${req.user.username} (User ${req.user.id}) accessed secret API Key of User ID ${targetId} (${targetUser.name}).`,
        userId: req.user.id,
        username: req.user.username,
        endpoint: `/api/users/${targetId}/apikey`,
        method: 'GET',
        statusCode: 200,
        targetUser,
      });
    }
  } else {
    db.logAudit({
      userId: req.user.id,
      username: req.user.username,
      sessionToken: req.token || null,
      action: 'VIEW_OWN_API_KEY',
      narrative: `${req.user.username} viewed their API key`,
      method: 'GET',
      endpoint: `/api/users/${targetId}/apikey`,
      statusCode: 200,
      ipAddress: ip,
    });
  }

  res.status(200).json({
    success: true,
    userId: targetUser.id,
    username: targetUser.username,
    name: targetUser.name,
    apiKey: targetUser.apiKey,
  });
});

// PUT /api/users/:id/email
app.put('/api/users/:id/email', (req: Request, res: Response) => {
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  if (!req.user) {
    return res.status(401).json({ success: false, error: 'Unauthorized: Missing or invalid token' });
  }

  const userId = Number(req.params.id);
  const { email } = req.body;

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ success: false, error: 'A valid email address is required' });
  }

  const targetUserBefore = db.getUserById(userId);
  const updatedUser = db.updateUserEmail(userId, email.trim());
  if (!updatedUser) {
    return res.status(404).json({ success: false, error: 'User not found' });
  }

  const isCrossUser = req.user.id !== userId;

  db.logAudit({
    userId: req.user.id,
    username: req.user.username,
    sessionToken: req.token || null,
    action: isCrossUser ? 'EMAIL_UPDATED_CROSS' : 'EMAIL_UPDATED',
    narrative: isCrossUser
      ? `${req.user.username} updated email for User ID ${userId} to ${email.trim()}`
      : `${req.user.username} updated email to ${email.trim()}`,
    method: 'PUT',
    endpoint: `/api/users/${userId}/email`,
    statusCode: 200,
    ipAddress: ip,
  });

  // Raise alert on cross-user modification
  if (isCrossUser) {
    db.createOrUpdateAlert({
      alertType: 'POSSIBLE_IDOR_ATTACK',
      title: 'Possible IDOR Attack: Unauthorized Email Modification',
      summary: `${req.user.username} (User ${req.user.id}) modified email for User ID ${userId} (${targetUserBefore?.name}) from '${targetUserBefore?.email}' to '${email.trim()}'.`,
      userId: req.user.id,
      username: req.user.username,
      endpoint: `/api/users/${userId}/email`,
      method: 'PUT',
      statusCode: 200,
      targetUser: targetUserBefore,
    });
  }

  const { password: _, ...safeUser } = updatedUser;
  res.status(200).json({
    success: true,
    message: `Email updated successfully for user ID ${userId}`,
    user: safeUser,
  });
});

/* ==========================================================================
   AUDIT TRAIL & ALERT APIS
   ========================================================================== */

// GET /api/audit/logs - Clean chronological audit trail
app.get('/api/audit/logs', (_req: Request, res: Response) => {
  const logs = db.getAuditLogs();
  res.status(200).json({
    success: true,
    count: logs.length,
    logs,
  });
});

// POST /api/audit/clear - Clears audit logs
app.post('/api/audit/clear', (_req: Request, res: Response) => {
  db.clearAuditLogs();
  res.status(200).json({
    success: true,
    message: 'Audit trail cleared',
  });
});

// GET /api/alerts - Returns all triggered security alerts
app.get('/api/alerts', (_req: Request, res: Response) => {
  const alerts = db.getAlerts();
  res.status(200).json({
    success: true,
    count: alerts.length,
    alerts,
  });
});

// GET /api/alerts/:id/explain - Generates or retrieves explanation (Gemini AI or Predefined)
app.get('/api/alerts/:id/explain', async (req: Request, res: Response) => {
  const alert = db.getAlertById(req.params.id);
  if (!alert) {
    return res.status(404).json({ success: false, error: 'Alert not found' });
  }

  try {
    const updatedExplanation = await explainWithGemini(alert);
    db.updateAlertExplanation(alert.id, updatedExplanation);
    res.status(200).json({
      success: true,
      alertId: alert.id,
      explanation: updatedExplanation,
    });
  } catch (err: any) {
    res.status(200).json({
      success: true,
      alertId: alert.id,
      explanation: alert.explanation,
    });
  }
});

// POST /api/alerts/clear - Clears alerts
app.post('/api/alerts/clear', (_req: Request, res: Response) => {
  db.clearAlerts();
  res.status(200).json({
    success: true,
    message: 'Alerts cleared',
  });
});

// POST /api/reset
app.post('/api/reset', (_req: Request, res: Response) => {
  const result = db.reset();
  res.json(result);
});

/* ==========================================================================
   STATIC & VITE DEV SERVER
   ========================================================================== */

async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Bank Server] Running on http://127.0.0.1:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Server failed to start:', err);
  process.exit(1);
});
