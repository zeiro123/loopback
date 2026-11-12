/**
 * Loopback correlation engine — sequence-level multi-step attack detection.
 *
 * Unlike per-event detectors, this engine reasons over the ORDERED session
 * window of correlated api+db events per actor:
 *
 *   1. IDOR / BOLA      — resource owner ≠ authenticated actor
 *   2. Business logic   — negative transfers (balance inflation), overdraft bypass
 *   3. Enumeration      — ≥3 distinct object targets in a sliding 60s window
 *   4. Cross-functional — flagged activity spans ≥2 distinct endpoint classes
 *
 * Every alert embeds the loopback chain: the API request, the SQL it produced
 * (joined on trace id), the object owner, and the impact — the evidence an
 * analyst needs to go from a suspicious query back to the user behind it.
 */
import {
  recentWindow, dbEventsForTrace, countRecentAlerts, insertAlert,
} from './db.js';

const WINDOW_SECONDS = 60;

function endpointClass(endpoint) {
  const parts = String(endpoint || '/').replace(/^\//, '').split('/');
  return parts.slice(0, 2).join('/') || 'root';
}

function targetOf(ev) {
  const ro = ev.resource_owner || {};
  const meta = ev.meta || {};
  return ro.accountNumber || (ro.userId != null ? `user:${ro.userId}` : null) || meta.toAccountNumber || null;
}

function severityRank(s) {
  return { INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 }[s] ?? 0;
}

function maxSeverity(a, b) {
  return severityRank(a) >= severityRank(b) ? a : b;
}

function bump(sev, isCross) {
  return isCross ? maxSeverity(sev, 'HIGH') : sev;
}

/* ==========================================================================
   Attack path builder — nodes actor → endpoint → query → target → impact
   ========================================================================== */

async function buildAttackPath(ev, kind) {
  const actor = `${ev.username || 'Unknown'} (ID: ${ev.actor_id ?? 'anon'})`;
  const endpoint = `${ev.method} ${ev.endpoint}`;
  const queries = await dbEventsForTrace(ev.trace_id);
  const queryTemplates = queries.map((q) => q.template);
  const queryLabel = queryTemplates.length
    ? `${queryTemplates.length} SQL statement(s): ${queryTemplates[0]}${queryTemplates.length > 1 ? ' …' : ''}`
    : 'No SQL captured for this trace';
  const ro = ev.resource_owner || {};
  const target = ro.accountNumber
    ? `Account ${ro.accountNumber} (owner user ${ro.userId ?? '?'})`
    : ro.userId != null
    ? `User ${ro.userId}`
    : 'Target object';

  const impacts = {
    IDOR: ev.status_code === 200
      ? 'Unauthorized object data exposed (HTTP 200)'
      : 'Object access probed / rejected',
    BIZLOGIC: 'Ledger invariant violated — balance manipulated',
    ENUM: 'Horizontal resource enumeration sweep',
  };

  const nodes = [
    { type: 'actor', label: actor, details: `Session ${String(ev.session_token || 'anon').slice(0, 12)}… • ${ev.ip || 'no ip'}` },
    { type: 'endpoint', label: endpoint, details: `${String(ev.api || 'rest').toUpperCase()}${ev.operation ? ` • ${ev.operation}` : ''} → HTTP ${ev.status_code}` },
    { type: 'query', label: 'Correlated SQL (trace join)', details: queryLabel },
    { type: 'target', label: target, details: ro.accountNumber ? 'Object reached without ownership check' : 'Object reached' },
    { type: 'impact', label: impacts[kind] || 'Anomalous activity', details: `trace ${String(ev.trace_id).slice(0, 8)}…` },
  ];
  const edges = nodes.slice(0, -1).map((n, i) => ({ from: i, to: i + 1, label: ['issued request', 'produced SQL', 'touched object', 'resulted in'][i] }));

  const steps = [
    { step: 1, phase: 'Session', title: 'Authenticated actor', description: `${actor} acted with a valid session token.`, status: 'SUCCESS', ts: ev.ts },
    { step: 2, phase: 'API call', title: `${endpoint}`, description: `${String(ev.api || 'rest').toUpperCase()} request${ev.operation ? ` (${ev.operation})` : ''} returned HTTP ${ev.status_code}.`, status: 'SUCCESS', ts: ev.ts },
    { step: 3, phase: 'Loopback join', title: 'Request bound to SQL', description: `trace ${ev.trace_id} produced: ${queryTemplates.join(' | ') || 'no SQL'}.`, status: 'FLAGGED', ts: ev.ts },
    { step: 4, phase: 'Object access', title: `Reached ${target}`, description: kind === 'IDOR' ? 'Object owner does not match the authenticated actor — object-level authorization missing.' : 'Business-rule evaluation over the correlated pair.', status: kind === 'IDOR' && ev.status_code === 200 ? 'FLAGGED' : 'SUCCESS', ts: ev.ts },
    { step: 5, phase: 'Detection', title: 'Loopback alert raised', description: `Sequence-level detector flagged this session activity (severity computed over the ${WINDOW_SECONDS}s window, not the single request).`, status: 'FLAGGED', ts: ev.ts },
  ];

  return { nodes, edges, steps };
}

/* ==========================================================================
   Alert factory
   ========================================================================== */

function makeId() {
  return `alert_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
}

async function raiseAlert({ ev, kind, title, summary, windowEvs }) {
  const priorCount = await countRecentAlerts(ev.actor_id, kind);
  const classes = new Set(windowEvs.map((w) => endpointClass(w.endpoint)));
  const isCross = classes.size > 1;
  const attempts = priorCount + 1;

  let severity;
  if (kind === 'IDOR') {
    severity = isCross && attempts >= 3 ? 'CRITICAL' : isCross ? 'HIGH' : attempts >= 3 ? 'HIGH' : attempts === 2 ? 'MEDIUM' : 'INFO';
  } else if (kind === 'BIZLOGIC') {
    severity = isCross || attempts >= 3 ? 'CRITICAL' : 'HIGH';
  } else {
    severity = isCross || attempts >= 4 ? 'CRITICAL' : 'HIGH';
  }

  const affected = [...new Set(windowEvs.map((w) => w.endpoint.split('?')[0]))].slice(-6);
  const attackPath = await buildAttackPath(ev, kind);

  const alert = {
    id: makeId(),
    ts: new Date().toISOString(),
    actorId: ev.actor_id,
    username: ev.username,
    alertType: kind === 'IDOR' ? 'POSSIBLE_IDOR_ATTACK' : kind === 'BIZLOGIC' ? 'POSSIBLE_BUSINESS_LOGIC_ATTACK' : 'RESOURCE_ENUMERATION_ATTACK',
    severity,
    title,
    summary,
    attempts,
    isCrossFunctional: isCross,
    affectedEndpoints: affected,
    evidence: {
      traceId: ev.trace_id,
      api: ev.api,
      operation: ev.operation,
      request: { method: ev.method, endpoint: ev.endpoint, statusCode: ev.status_code },
      resourceOwner: ev.resource_owner,
      meta: ev.meta,
      windowEndpoints: affected,
      windowSize: windowEvs.length,
      windowSeconds: WINDOW_SECONDS,
    },
    attackPath,
  };
  await insertAlert(alert);
  console.log(`[soc/correlate] ${severity} ${alert.alertType} — ${ev.username} @ ${ev.endpoint}`);
  return alert;
}

/* ==========================================================================
   Detection entry point — called per ingested api event
   ========================================================================== */

export async function evaluateEvent(ev) {
  if (ev.actor_id == null) return; // anonymous events (login failures etc.) — no session to correlate
  const windowEvs = await recentWindow(ev.actor_id, WINDOW_SECONDS);
  if (!windowEvs.length) return;

  const flags = [];

  /* --- 1. IDOR / BOLA: object owner ≠ actor ------------------------------- */
  const ro = ev.resource_owner || {};
  if (ro.userId != null && ev.actor_id != null && Number(ro.userId) !== Number(ev.actor_id)) {
    const what = ro.accountNumber
      ? `accessed account ${ro.accountNumber} owned by user ${ro.userId}`
      : `accessed objects of user ${ro.userId}`;
    flags.push({
      kind: 'IDOR',
      title: ro.accountNumber
        ? 'Possible IDOR Attack: Unauthorized Account Object Access'
        : 'Possible IDOR Attack: Cross-User Object Access',
      summary: `${ev.username} (user ${ev.actor_id}) ${what} via ${ev.method} ${ev.endpoint} (HTTP ${ev.status_code}). Object-level authorization was not enforced.`,
    });
  }

  /* --- 2. Business logic: ledger invariant violations --------------------- */
  const meta = ev.meta || {};
  if (meta.amount != null && endpointClass(ev.endpoint) === 'api/transfers') {
    const amount = Number(meta.amount);
    const balanceBefore = meta.balanceBefore != null ? Number(meta.balanceBefore) : null;
    if (amount <= 0) {
      flags.push({
        kind: 'BIZLOGIC',
        title: 'Business Logic Attack: Negative Amount Balance Inflation',
        summary: `${ev.username} submitted a negative transfer of ZWL ${amount.toFixed(2)}${meta.toAccountNumber ? ` to ${meta.toAccountNumber}` : ''}. Balance moved ${balanceBefore != null ? `ZWL ${balanceBefore.toFixed(2)} → ZWL ${Number(meta.balanceAfter ?? 0).toFixed(2)}` : ''}: the debit inverted into a credit.`,
      });
    } else if (balanceBefore != null && amount > balanceBefore) {
      flags.push({
        kind: 'BIZLOGIC',
        title: 'Business Logic Attack: Overdraft Invariant Bypass',
        summary: `${ev.username} transferred ZWL ${amount.toFixed(2)} from a balance of ZWL ${balanceBefore.toFixed(2)} — no insufficient-funds check. Account overdrawn to ZWL ${Number(meta.balanceAfter ?? 0).toFixed(2)}.`,
      });
    }
  }

  /* --- 3. Enumeration: ≥3 distinct targets in the sliding window ---------- */
  const byClass = new Map();
  for (const w of windowEvs) {
    const cls = endpointClass(w.endpoint);
    if (!byClass.has(cls)) byClass.set(cls, new Set());
    const t = targetOf(w);
    if (t) byClass.get(cls).add(String(t));
  }
  for (const [cls, targets] of byClass) {
    if (targets.size >= 3) {
      flags.push({
        kind: 'ENUM',
        title: 'Resource Enumeration: Horizontal Sweep Detected',
        summary: `${ev.username} probed ${targets.size} distinct object targets on ${cls} within ${WINDOW_SECONDS}s (${[...targets].slice(0, 6).join(', ')}). Velocity exceeds any single-request baseline.`,
      });
      break; // one enumeration alert per event
    }
  }

  for (const f of flags) {
    await raiseAlert({ ev, kind: f.kind, title: f.title, summary: f.summary, windowEvs });
  }
}
