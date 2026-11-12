/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface User {
  id: number;
  username: string; // "Mary", "John", etc.
  name: string;
  email: string;
  password: string; // "peter"
  apiKey: string; // e.g. "live_sec_key_mary_..."
  address: string; // Fixed address e.g. "14 Samora Machel Avenue, Harare, Zimbabwe"
  role: 'customer' | 'admin';
  createdAt: string;
}

export interface Account {
  id: string; // "acc_101", "acc_102"
  userId: number;
  accountNumber: string; // "ACC-1001", "ACC-2002"
  type: 'CHECKING' | 'SAVINGS';
  balance: number;
  currency: string;
}

export interface Transaction {
  id: string;
  accountId: string;
  fromUserId: number;
  toAccountNumber: string;
  amount: number;
  type: 'TRANSFER' | 'DEPOSIT';
  description: string;
  timestamp: string;
}

export interface Session {
  token: string;
  userId: number;
  role: 'customer' | 'admin';
  createdAt: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  userId: number | null;
  username: string;
  sessionToken: string | null;
  action: string;
  narrative: string;
  method: string;
  endpoint: string;
  statusCode: number;
  ipAddress: string;
  metadata?: Record<string, any>;
}

export interface AttackGraphStep {
  stepNumber: number;
  phase: string;
  title: string;
  description: string;
  actor: string;
  target: string;
  status: 'SUCCESS' | 'BLOCKED' | 'FLAGGED';
  timestamp: string;
}

export interface AttackGraphNode {
  id: string;
  label: string;
  type: 'actor' | 'endpoint' | 'target' | 'impact';
  details: string;
}

export interface AttackGraphEdge {
  from: string;
  to: string;
  label: string;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  alertType: 'POSSIBLE_IDOR_ATTACK' | 'POSSIBLE_BUSINESS_LOGIC_ATTACK' | 'RESOURCE_ENUMERATION_ATTACK' | 'SUSPICIOUS_AUTH_ANOMALY';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  summary: string;
  userId: number | null;
  username: string;
  endpoint: string;
  method: string;
  statusCode: number;
  attemptsCount: number;
  isCrossFunctional: boolean;
  affectedEndpoints: string[];
  explanation: {
    source: 'AI_GEMINI' | 'PREDEFINED_RULE';
    overview: string;
    rootCause: string;
    attackMechanics: string;
    businessImpact: string;
    remediation: string;
    generatedAt: string;
  };
  attackGraph: {
    steps: AttackGraphStep[];
    nodes: AttackGraphNode[];
    edges: AttackGraphEdge[];
  };
}

// In-memory sliding window for enumeration tracking
interface EnumerationTrace {
  timestamp: number;
  targetId: string | number;
  endpoint: string;
}

class Database {
  users: Map<number, User> = new Map();
  accounts: Map<string, Account> = new Map();
  transactions: Transaction[] = [];
  sessions: Map<string, Session> = new Map();
  auditLogs: AuditEntry[] = [];
  alerts: SecurityAlert[] = [];
  enumerationTracker: Map<string, EnumerationTrace[]> = new Map(); // key: user/IP
  userProbingHistory: Map<string, { endpoints: Set<string>; attempts: number; lastSeen: number }> = new Map();

  constructor() {
    this.seed();
  }

  seed() {
    this.users.clear();
    this.accounts.clear();
    this.transactions = [];
    this.sessions.clear();
    this.auditLogs = [];
    this.alerts = [];
    this.enumerationTracker.clear();
    this.userProbingHistory.clear();

    // 1. Mary Jane (User 1) - Harare, Zimbabwe
    const mary: User = {
      id: 1,
      username: 'Mary',
      name: 'Mary Jane',
      email: 'mary.jane@apexbank.test',
      password: 'peter',
      apiKey: 'live_sec_key_mary_8819a7e3bc214f',
      address: '14 Samora Machel Avenue, Harare, Zimbabwe',
      role: 'customer',
      createdAt: new Date().toISOString(),
    };
    this.users.set(mary.id, mary);

    // 2. John Doe (User 2) - Mutare, Zimbabwe
    const john: User = {
      id: 2,
      username: 'John',
      name: 'John Doe',
      email: 'john.doe@apexbank.test',
      password: 'peter',
      apiKey: 'live_sec_key_john_4472b99a12cd6e',
      address: '82 Herbert Chitepo Street, Mutare, Zimbabwe',
      role: 'customer',
      createdAt: new Date().toISOString(),
    };
    this.users.set(john.id, john);

    // Additional users for IDOR & Enumeration testing (IDs 3..8)
    const extraUsers: Array<Omit<User, 'role' | 'createdAt'>> = [
      { id: 3, username: 'Alice', name: 'Alice Smith', email: 'alice.smith@apexbank.test', password: 'peter', apiKey: 'live_sec_key_alice_9931c44b58e23a', address: '45 Joshua Nkomo Street, Bulawayo, Zimbabwe' },
      { id: 4, username: 'Bob', name: 'Bob Vance', email: 'bob.vance@apexbank.test', password: 'peter', apiKey: 'live_sec_key_bob_5521d12a77f98c', address: '12 Robert Mugabe Way, Gweru, Zimbabwe' },
      { id: 5, username: 'Charlie', name: 'Charlie Brown', email: 'charlie.brown@apexbank.test', password: 'peter', apiKey: 'live_sec_key_charlie_1142e88d44a12b', address: '7 Josiah Tongogara Avenue, Masvingo, Zimbabwe' },
      { id: 6, username: 'Diana', name: 'Diana Prince', email: 'diana.prince@apexbank.test', password: 'peter', apiKey: 'live_sec_key_diana_7733f33c99b84d', address: '3 Livingstone Way, Victoria Falls, Zimbabwe' },
      { id: 7, username: 'Evan', name: 'Evan Wright', email: 'evan.wright@apexbank.test', password: 'peter', apiKey: 'live_sec_key_evan_6620g55b11c73e', address: '19 Magamba Way, Chinhoyi, Zimbabwe' },
      { id: 8, username: 'Fiona', name: 'Fiona Gallagher', email: 'fiona.gallagher@apexbank.test', password: 'peter', apiKey: 'live_sec_key_fiona_3311h77e22f64a', address: '5 Nelson Mandela Road, Kwekwe, Zimbabwe' },
    ];

    extraUsers.forEach((u) => {
      this.users.set(u.id, {
        ...u,
        role: 'customer',
        createdAt: new Date().toISOString(),
      });
      const accNum = `ACC-${3000 + u.id}`;
      this.accounts.set(`acc_${100 + u.id}`, {
        id: `acc_${100 + u.id}`,
        userId: u.id,
        accountNumber: accNum,
        type: 'SAVINGS',
        balance: 1000 + u.id * 150,
        currency: 'USD',
      });
    });

    // Account 1: Mary's checking ($500)
    const maryAccount: Account = {
      id: 'acc_101',
      userId: 1,
      accountNumber: 'ACC-1001',
      type: 'CHECKING',
      balance: 500.00,
      currency: 'USD',
    };
    this.accounts.set(maryAccount.id, maryAccount);

    // Account 2: John's checking ($500)
    const johnAccount: Account = {
      id: 'acc_102',
      userId: 2,
      accountNumber: 'ACC-2002',
      type: 'CHECKING',
      balance: 500.00,
      currency: 'USD',
    };
    this.accounts.set(johnAccount.id, johnAccount);

    // Initial deposit transactions
    this.transactions.push(
      {
        id: 'txn_01',
        accountId: 'acc_101',
        fromUserId: 1,
        toAccountNumber: 'ACC-1001',
        amount: 500.00,
        type: 'DEPOSIT',
        description: 'Opening deposit',
        timestamp: new Date(Date.now() - 3 * 86400000).toISOString(),
      },
      {
        id: 'txn_02',
        accountId: 'acc_102',
        fromUserId: 2,
        toAccountNumber: 'ACC-2002',
        amount: 500.00,
        type: 'DEPOSIT',
        description: 'Opening deposit',
        timestamp: new Date(Date.now() - 3 * 86400000).toISOString(),
      }
    );
  }

  getUserById(id: number): User | undefined {
    return this.users.get(id);
  }

  getUserByUsername(username: string): User | undefined {
    const term = username.trim().toLowerCase();
    return Array.from(this.users.values()).find(
      (u) => u.username.toLowerCase() === term || u.name.toLowerCase() === term
    );
  }

  updateUserEmail(userId: number, email: string): User | undefined {
    const user = this.users.get(userId);
    if (user) {
      user.email = email;
    }
    return user;
  }

  getAccountByUserId(userId: number): Account | undefined {
    return Array.from(this.accounts.values()).find((a) => a.userId === userId);
  }

  getAccountById(accountId: string): Account | undefined {
    return this.accounts.get(accountId);
  }

  getAccountByNumber(accountNumber: string): Account | undefined {
    return Array.from(this.accounts.values()).find((a) => a.accountNumber === accountNumber);
  }

  getTransactions(accountId: string): Transaction[] {
    return this.transactions.filter((t) => t.accountId === accountId);
  }

  getStatement(accountNumber: string) {
    const account = this.getAccountByNumber(accountNumber);
    if (!account) return undefined;
    const owner = this.getUserById(account.userId);
    if (!owner) return undefined;
    const txns = this.getTransactions(account.id);
    return {
      statementId: `STM-2026-${account.accountNumber.replace('ACC-', '')}92`,
      generatedAt: new Date().toISOString(),
      bankName: 'Apex Commercial Bank of Zimbabwe',
      bankAddress: 'Apex Towers, 102 Jason Moyo Avenue, Harare, Zimbabwe',
      period: 'Statement Period: Current Active Quarter',
      accountHolder: {
        name: owner.name,
        username: owner.username,
        email: owner.email,
        address: owner.address,
        userId: owner.id,
      },
      account: {
        accountNumber: account.accountNumber,
        type: account.type,
        balance: account.balance,
        currency: account.currency,
      },
      transactions: txns,
    };
  }

  createTransaction(txn: Omit<Transaction, 'id' | 'timestamp'>): Transaction {
    const newTxn: Transaction = {
      ...txn,
      id: `txn_${Date.now()}`,
      timestamp: new Date().toISOString(),
    };
    this.transactions.unshift(newTxn);
    return newTxn;
  }

  createSession(userId: number, role: 'customer' | 'admin' = 'customer'): Session {
    const token = `token_${role === 'admin' ? 'admin' : userId}_${Math.random().toString(36).substring(2, 10)}_${Date.now()}`;
    const session: Session = {
      token,
      userId,
      role,
      createdAt: new Date().toISOString(),
    };
    this.sessions.set(token, session);
    return session;
  }

  getSession(token: string): Session | undefined {
    return this.sessions.get(token);
  }

  deleteSession(token: string): boolean {
    return this.sessions.delete(token);
  }

  logAudit(entry: Omit<AuditEntry, 'id' | 'timestamp'>): AuditEntry {
    const newEntry: AuditEntry = {
      ...entry,
      id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
    };
    this.auditLogs.unshift(newEntry);
    if (this.auditLogs.length > 250) {
      this.auditLogs.pop();
    }
    return newEntry;
  }

  getAuditLogs(): AuditEntry[] {
    return this.auditLogs;
  }

  clearAuditLogs() {
    this.auditLogs = [];
    this.enumerationTracker.clear();
  }

  // Record an anomaly alert and track repeat probing & cross-functionality
  createOrUpdateAlert(params: {
    alertType: SecurityAlert['alertType'];
    title: string;
    summary: string;
    userId: number | null;
    username: string;
    endpoint: string;
    method: string;
    statusCode: number;
    targetUser?: User | null;
    targetAccount?: Account | null;
    exploitDetails?: string;
  }): SecurityAlert {
    const trackerKey = `${params.userId || 'anon'}`;
    let probing = this.userProbingHistory.get(trackerKey);
    if (!probing) {
      probing = { endpoints: new Set<string>(), attempts: 0, lastSeen: Date.now() };
      this.userProbingHistory.set(trackerKey, probing);
    }

    probing.attempts += 1;
    probing.endpoints.add(params.endpoint.split('?')[0]);
    probing.lastSeen = Date.now();

    const isSuccessful = params.statusCode === 200;
    const distinctEndpointsCount = probing.endpoints.size;
    const isCrossFunctional = distinctEndpointsCount > 1;

    // Progressive Severity Calculation:
    // 1. Lenient single attempts: If John/Mary tries to query another user once on a single endpoint,
    //    mark as 'INFO' (Informational: isolated exploratory action).
    // 2. Escalates with repetition: 2 attempts -> 'MEDIUM', 3+ attempts -> 'HIGH'.
    // 3. Escalates with platform-wide breadth: probing across >= 2 distinct functionalities -> 'HIGH', >= 3 -> 'CRITICAL'.
    let severity: SecurityAlert['severity'] = 'INFO';

    if (params.alertType === 'POSSIBLE_BUSINESS_LOGIC_ATTACK') {
      // Direct financial balance manipulation
      if (isCrossFunctional || probing.attempts >= 3) {
        severity = 'CRITICAL';
      } else if (probing.attempts >= 2) {
        severity = 'HIGH';
      } else {
        severity = isSuccessful ? 'HIGH' : 'MEDIUM';
      }
    } else if (params.alertType === 'RESOURCE_ENUMERATION_ATTACK') {
      // High-volume sequential traversal
      severity = isCrossFunctional || probing.attempts >= 4 ? 'CRITICAL' : 'HIGH';
    } else {
      // IDOR / BOLA / Probing:
      if (distinctEndpointsCount >= 3 || (isCrossFunctional && probing.attempts >= 4)) {
        severity = 'CRITICAL'; // Multi-vector platform-wide attack campaign
      } else if (isCrossFunctional || probing.attempts >= 3) {
        severity = 'HIGH';     // Broadening target footprint or repeated extraction
      } else if (probing.attempts === 2) {
        severity = 'MEDIUM';   // Repetitive probe confirms deliberate pattern
      } else {
        // Attempt 1 (lenient / informational):
        severity = 'INFO';
      }
    }

    // Generate Predefined Rule-Based Explanation (Rock-solid offline)
    const explanation = this.generatePredefinedExplanation(params.alertType, params, isSuccessful, isCrossFunctional);

    // Generate Step-by-Step Attack Graph
    const attackGraph = this.generateAttackGraph(params, isSuccessful);

    const alert: SecurityAlert = {
      id: `alert_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      alertType: params.alertType,
      severity,
      title: params.title,
      summary: params.summary,
      userId: params.userId,
      username: params.username,
      endpoint: params.endpoint,
      method: params.method,
      statusCode: params.statusCode,
      attemptsCount: probing.attempts,
      isCrossFunctional,
      affectedEndpoints: Array.from(probing.endpoints),
      explanation,
      attackGraph,
    };

    this.alerts.unshift(alert);
    if (this.alerts.length > 100) {
      this.alerts.pop();
    }
    return alert;
  }

  getAlerts(): SecurityAlert[] {
    return this.alerts;
  }

  getAlertById(id: string): SecurityAlert | undefined {
    return this.alerts.find((a) => a.id === id);
  }

  updateAlertExplanation(alertId: string, explanation: SecurityAlert['explanation']) {
    const alert = this.getAlertById(alertId);
    if (alert) {
      alert.explanation = explanation;
    }
    return alert;
  }

  clearAlerts() {
    this.alerts = [];
    this.userProbingHistory.clear();
  }

  private generatePredefinedExplanation(
    type: SecurityAlert['alertType'],
    params: any,
    isSuccessful: boolean,
    isCrossFunctional: boolean
  ): SecurityAlert['explanation'] {
    let overview = '';
    let rootCause = '';
    let attackMechanics = '';
    let businessImpact = '';
    let remediation = '';

    if (type === 'POSSIBLE_IDOR_ATTACK') {
      overview = `User '${params.username}' (User ID: ${params.userId}) issued a request to endpoint '${params.endpoint}' specifying an object identifier that belongs to another entity. ${
        isSuccessful
          ? 'The server authorized and executed the request, granting unauthorized access.'
          : 'The server rejected or failed to locate the resource, but anomalous identifier tampering was captured.'
      }`;
      rootCause = `The endpoint lacks an ownership validation layer. It accepts resource IDs directly from client parameters (URL path or body) without verifying whether the authenticated session matches the owner of that resource.`;
      attackMechanics = `1. The client authenticated with valid session credentials for User ID ${params.userId}.\n2. In transit, the target identifier parameter in '${params.endpoint}' was substituted with another user's ID.\n3. The backend checked session validity but failed to perform object-level permission check: (resource.userId === session.userId).`;
      businessImpact = `Broken Object Level Authorization (OWASP API1). If exploited, attackers can harvest private statements, customer contact details, or sensitive developer API keys across all tenants.`;
      remediation = `Enforce object-level authorization in Express before reading/mutating data:\nif (targetResource.userId !== req.user.id) {\n  return res.status(403).json({ error: 'Access Denied: Object not owned by session' });\n}`;
    } else if (type === 'POSSIBLE_BUSINESS_LOGIC_ATTACK') {
      overview = `A transaction anomaly was captured on '${params.endpoint}'. User '${params.username}' initiated a balance manipulation that violated fundamental financial ledger constraints.`;
      rootCause = `The API handler failed to enforce strict invariant checks (such as verifying transfer amounts are strictly positive and verifying account balances cannot be overdrawn beyond credit lines).`;
      attackMechanics = `1. The attacker submitted a manipulated payload (${params.exploitDetails || 'amount manipulation'}).\n2. The server executed the arithmetic without boundary assertions.\n3. The ledger debited/credited balances abnormally.`;
      businessImpact = `Direct financial loss, arbitrary balance inflation, liquidity theft, and ledger corruption.`;
      remediation = `Validate financial invariants at the domain service layer:\nif (typeof amount !== 'number' || amount <= 0 || !Number.isFinite(amount)) {\n  return res.status(400).json({ error: 'Invalid transfer amount' });\n}\nif (sourceAccount.balance < amount) {\n  return res.status(400).json({ error: 'Insufficient funds' });\n}`;
    } else {
      overview = `An anomalous request sequence was flagged during session correlation.`;
      rootCause = `Pattern matches automated scanning or horizontal enumeration.`;
      attackMechanics = `Rapid queries across sequential or predictable identifiers.`;
      businessImpact = `Reconnaissance for credential stuffing or mass data harvesting.`;
      remediation = `Implement rate-limiting and use non-sequential UUIDs for resource identifiers.`;
    }

    if (isCrossFunctional) {
      overview += ` Notice: This user has attempted to tamper with identifiers across multiple functional endpoints, indicating coordinated lateral movement.`;
    }

    return {
      source: 'PREDEFINED_RULE',
      overview,
      rootCause,
      attackMechanics,
      businessImpact,
      remediation,
      generatedAt: new Date().toISOString(),
    };
  }

  private generateAttackGraph(params: any, isSuccessful: boolean): SecurityAlert['attackGraph'] {
    const actorLabel = `${params.username || 'Client'} (ID: ${params.userId || 'Anon'})`;
    const endpointLabel = `${params.method} ${params.endpoint}`;
    const targetLabel = params.targetUser
      ? `${params.targetUser.name} (ID: ${params.targetUser.id})`
      : params.targetAccount
      ? `Account ${params.targetAccount.accountNumber}`
      : 'Target Resource';

    if (params.alertType === 'POSSIBLE_BUSINESS_LOGIC_ATTACK') {
      const isNegative = params.title.includes('Negative');
      const impactLabel = isNegative ? 'Balance Inflated (Unauthorized Credit)' : 'Overdraft Invariant Breached';
      const mathDetails = isNegative
        ? 'Debit subtraction inverted to addition: balance = balance - (-amount)'
        : 'Overdraft limit bypassed without credit line authorization';

      const steps: AttackGraphStep[] = [
        {
          stepNumber: 1,
          phase: 'Authentication & Session Initialization',
          title: 'Session Established',
          description: `${actorLabel} obtained valid bearer session credentials.`,
          actor: actorLabel,
          target: 'Auth Service',
          status: 'SUCCESS',
          timestamp: new Date(Date.now() - 3000).toISOString(),
        },
        {
          stepNumber: 2,
          phase: 'Payload Parameter Tampering',
          title: 'Value Tampering in Transfer Request',
          description: `Client intercepted request and tampered with the 'amount' field (${params.exploitDetails || 'negative value'}) before dispatching to ${endpointLabel}.`,
          actor: actorLabel,
          target: endpointLabel,
          status: 'SUCCESS',
          timestamp: new Date(Date.now() - 1500).toISOString(),
        },
        {
          stepNumber: 3,
          phase: 'Ledger Invariant Evaluation',
          title: 'Business Logic & Arithmetic Invariant Bypass',
          description: `Backend executed ledger calculation without strictly asserting amount > 0. ${mathDetails} (HTTP ${params.statusCode}).`,
          actor: endpointLabel,
          target: 'Ledger State Engine',
          status: isSuccessful ? 'FLAGGED' : 'BLOCKED',
          timestamp: new Date().toISOString(),
        },
        {
          stepNumber: 4,
          phase: 'Correlation & Telemetry Detection',
          title: 'Anomaly Flagged by Loopback Engine',
          description: `Loopback correlation engine flagged financial ledger invariant violation: balance inflation on source account contrary to accounting conservation rules.`,
          actor: 'Loopback Engine',
          target: 'SOC Console',
          status: 'FLAGGED',
          timestamp: new Date().toISOString(),
        },
      ];

      const nodes: AttackGraphNode[] = [
        { id: 'node_actor', label: actorLabel, type: 'actor', details: `Source Session: ${params.username}` },
        { id: 'node_endpoint', label: endpointLabel, type: 'endpoint', details: `Tampered Payload: ${params.exploitDetails || 'amount manipulation'}` },
        { id: 'node_target', label: 'Ledger Arithmetic Invariant', type: 'target', details: isNegative ? 'Constraint: amount > 0' : 'Constraint: balance >= amount' },
        { id: 'node_impact', label: impactLabel, type: 'impact', details: isSuccessful ? 'High Impact: Money Created / Balances Inverted' : 'Transaction Blocked' },
      ];

      const edges: AttackGraphEdge[] = [
        { from: 'node_actor', to: 'node_endpoint', label: 'Transmits Tampered Amount' },
        { from: 'node_endpoint', to: 'node_target', label: 'Bypasses Boundary Assertion' },
        { from: 'node_target', to: 'node_impact', label: isSuccessful ? 'Corrupts Ledger State' : 'Blocked' },
      ];

      return { steps, nodes, edges };
    }

    if (params.alertType === 'RESOURCE_ENUMERATION_ATTACK') {
      const steps: AttackGraphStep[] = [
        {
          stepNumber: 1,
          phase: 'Authentication & Session Initialization',
          title: 'Session Established',
          description: `${actorLabel} obtained valid bearer session credentials.`,
          actor: actorLabel,
          target: 'Auth Service',
          status: 'SUCCESS',
          timestamp: new Date(Date.now() - 3000).toISOString(),
        },
        {
          stepNumber: 2,
          phase: 'Reconnaissance & Probing',
          title: 'Sequential Identifier Traversal',
          description: `Client automated sequential enumeration queries across multiple non-owned user IDs via ${endpointLabel}.`,
          actor: actorLabel,
          target: endpointLabel,
          status: 'SUCCESS',
          timestamp: new Date(Date.now() - 1500).toISOString(),
        },
        {
          stepNumber: 3,
          phase: 'Sliding Window Frequency Check',
          title: 'Cross-Tenant Probing Velocity Exceeded',
          description: `Request rate across unique object identifiers exceeded safety baseline (>3 distinct resource IDs within 60s window).`,
          actor: endpointLabel,
          target: 'Sliding Window Detector',
          status: 'FLAGGED',
          timestamp: new Date().toISOString(),
        },
        {
          stepNumber: 4,
          phase: 'Correlation & Telemetry Detection',
          title: 'Enumeration Attack Flagged',
          description: `Loopback correlation engine aggregated cross-object telemetry and flagged active reconnaissance.`,
          actor: 'Loopback Engine',
          target: 'SOC Console',
          status: 'FLAGGED',
          timestamp: new Date().toISOString(),
        },
      ];

      const nodes: AttackGraphNode[] = [
        { id: 'node_actor', label: actorLabel, type: 'actor', details: `Source Session: ${params.username}` },
        { id: 'node_endpoint', label: endpointLabel, type: 'endpoint', details: `HTTP Status: ${params.statusCode}` },
        { id: 'node_target', label: 'Sequential Tenant IDs (1, 2, 3...)', type: 'target', details: 'Automated Horizontal Sweep' },
        { id: 'node_impact', label: 'Reconnaissance Flagged', type: 'impact', details: 'Critical Severity: Tenant Data Harvest' },
      ];

      const edges: AttackGraphEdge[] = [
        { from: 'node_actor', to: 'node_endpoint', label: 'Sends Automated Probes' },
        { from: 'node_endpoint', to: 'node_target', label: 'Iterates ID Sequence' },
        { from: 'node_target', to: 'node_impact', label: 'Triggers Enumeration Rule' },
      ];

      return { steps, nodes, edges };
    }

    // Default / IDOR / BOLA Attack Graph
    const impactLabel = isSuccessful ? 'Object Data Exfiltrated / Mutated' : 'Access Probed / Failed';
    const isStatementTamper = params.endpoint?.includes('statement') || params.targetAccount;
    const paramDescription = isStatementTamper
      ? `Client intercepted request and substituted own account number with target account identifier (${targetLabel}).`
      : `Client intercepted request and substituted own user ID (${params.userId}) with target identifier (${targetLabel}).`;

    const targetNodeDetails = params.targetUser?.address
      ? `Owner: ${params.targetUser.name} • Location: ${params.targetUser.address}`
      : 'Cross-Tenant Object';

    const steps: AttackGraphStep[] = [
        {
          stepNumber: 1,
          phase: 'Authentication & Session Initialization',
          title: 'Session Established',
          description: `${actorLabel} obtained valid bearer session credentials.`,
          actor: actorLabel,
          target: 'Auth Service',
          status: 'SUCCESS',
          timestamp: new Date(Date.now() - 3000).toISOString(),
        },
        {
          stepNumber: 2,
          phase: 'Parameter Tampering / Interception',
          title: isStatementTamper ? 'Account Number Swapped in Statement Request' : 'Identifier Altered in Request',
          description: paramDescription,
          actor: actorLabel,
          target: endpointLabel,
          status: 'SUCCESS',
          timestamp: new Date(Date.now() - 1500).toISOString(),
        },
        {
          stepNumber: 3,
          phase: 'Server Boundary Evaluation',
          title: 'Authorization Boundary Evaluation',
          description: isSuccessful
            ? `Server checked session token but failed to verify object ownership (resource.ownerId === session.userId). Granted access to confidential records with HTTP ${params.statusCode}.`
            : `Server returned HTTP ${params.statusCode}. Probing logged.`,
          actor: endpointLabel,
          target: targetLabel,
          status: isSuccessful ? 'FLAGGED' : 'BLOCKED',
          timestamp: new Date().toISOString(),
        },
        {
          stepNumber: 4,
          phase: 'Correlation & Telemetry Detection',
          title: 'Anomaly Flagged by Loopback Engine',
          description: `Correlation engine cross-referenced session token identity (${params.userId}) against requested object owner (${targetLabel}). Alert raised.`,
          actor: 'Loopback Engine',
          target: 'SOC Console',
          status: 'FLAGGED',
          timestamp: new Date().toISOString(),
        },
      ];

      const nodes: AttackGraphNode[] = [
        { id: 'node_actor', label: actorLabel, type: 'actor', details: `Source Session: ${params.username}` },
        { id: 'node_endpoint', label: endpointLabel, type: 'endpoint', details: `HTTP Status: ${params.statusCode}` },
        { id: 'node_target', label: targetLabel, type: 'target', details: targetNodeDetails },
        { id: 'node_impact', label: impactLabel, type: 'impact', details: isSuccessful ? 'High Impact: Unauthorized Data Access' : 'Low Impact: Failed Probe' },
      ];

      const edges: AttackGraphEdge[] = [
        { from: 'node_actor', to: 'node_endpoint', label: 'Dispatches Request' },
        { from: 'node_endpoint', to: 'node_target', label: 'Queries Target Object' },
        { from: 'node_target', to: 'node_impact', label: isSuccessful ? 'Leaked / Mutated' : 'Blocked' },
      ];

    return { steps, nodes, edges };
  }

  trackEnumeration(trackerKey: string, targetId: string | number, endpoint: string): { isEnumeration: boolean; count: number; targets: string[] } {
    const now = Date.now();
    const windowMs = 60000;
    let traces = this.enumerationTracker.get(trackerKey) || [];

    traces = traces.filter((t) => now - t.timestamp < windowMs);
    traces.push({ timestamp: now, targetId, endpoint });
    this.enumerationTracker.set(trackerKey, traces);

    const uniqueTargets = Array.from(new Set(traces.map((t) => String(t.targetId))));
    return {
      isEnumeration: uniqueTargets.length >= 3,
      count: uniqueTargets.length,
      targets: uniqueTargets,
    };
  }

  reset() {
    this.seed();
    return { success: true, message: 'Reset successfully. Mary and John restored to $500 balance, seed users initialized.' };
  }
}

export const db = new Database();
