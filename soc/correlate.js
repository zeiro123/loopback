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
 * Every alert embeds the loopback chain: the device (IP + user-agent), the API
 * request, the SQL it produced (joined on trace id), the data tables touched,
 * the object owner, and the impact. Returns the raised alerts so the caller can
 * run the autonomous-response policy on them.
 */
import {
  recentWindow, dbEventsForTrace, countRecentAlerts, insertAlert, distinctIpsForSession,
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

function tablesOf(queries) {
  const tables = new Set();
  for (const q of queries) {
    for (const m of String(q.query || '').matchAll(/(?:\bFROM\b|\bJOIN\b|\bINTO\b|\bUPDATE\b)\s+([a-z_][a-z0-9_]*)/gi)) {
      if (!['now', 'interval'].includes(m[1].toLowerCase())) tables.add(m[1]);
    }
  }
  return [...tables];
}

function severityRank(s) {
  return { INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 }[s] ?? 0;
}

function makeId() {
  return `alert_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
}

/* ==========================================================================
   Attack path builder — device → session → API → SQL → data → impact
   ========================================================================== */

async function buildAttackPath(ev, kind) {
  const actor = `${ev.username || 'Unknown'} (ID: ${ev.actor_id ?? 'anon'})`;
  const endpoint = `${ev.method} ${ev.endpoint}`;
  const queries = await dbEventsForTrace(ev.trace_id);
  const queryTemplates = queries.map((q) => q.template);
  const tables = tablesOf(queries);
  const queryLabel = queryTemplates.length
    ? `${queryTemplates.length} SQL statement(s) on ${tables.length || 'no'} table(s)`
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

  // Layered data-traversal graph: device → session → api → sql → data → impact
  const nodes = [
    {
      layer: 'device', type: 'device', label: 'Client device',
      details: `IP ${ev.ip || 'unknown'} • ${String(ev.user_agent || 'unknown user-agent').slice(0, 90)}`,
    },
    {
      layer: 'session', type: 'session', label: 'Session',
      details: `token ${String(ev.session_token || 'anon').slice(0, 14)}… • actor ${actor}`,
    },
    {
      layer: 'api', type: 'endpoint', label: endpoint,
      details: `${String(ev.api || 'rest').toUpperCase()}${ev.operation ? ` • ${ev.operation}` : ''} → HTTP ${ev.status_code} • server: loopback-target`,
    },
    {
      layer: 'sql', type: 'query', label: 'Correlated SQL',
      details: queryTemplates.length
        ? `${queryTemplates.length} statement(s): ${queryTemplates[0]}${queryTemplates.length > 1 ? ' …' : ''}`
        : 'No SQL captured for this trace',
      statements: queryTemplates,
    },
    {
      layer: 'data', type: 'data', label: tables.length ? `Tables: ${tables.join(', ')}` : 'No tables touched',
      details: `PostgreSQL (loopback db) • rows returned by this trace: ${queries.reduce((n, q) => n + (q.row_count || 0), 0)} • target: ${target}`,
    },
    {
      layer: 'impact', type: 'impact', label: impacts[kind] || 'Anomalous activity',
      details: `trace ${String(ev.trace_id).slice(0, 8)}… • detection: sequence rules over the ${WINDOW_SECONDS}s session window`,
    },
  ];
  const edges = nodes.slice(0, -1).map((n, i) => ({
    from: i,
    to: i + 1,
    label: ['originates from', 'authenticates to', 'produces', 'reads / writes', 'results in'][i],
  }));

  const steps = [
    { step: 1, phase: 'Device', title: 'Request originated', description: `Client device at ${ev.ip || 'unknown IP'} (${String(ev.user_agent || 'unknown UA').slice(0, 70)}) sent the request.`, status: 'SUCCESS', ts: ev.ts },
    { step: 2, phase: 'Session', title: 'Authenticated actor', description: `${actor} acted with a valid session token.`, status: 'SUCCESS', ts: ev.ts },
    { step: 3, phase: 'API call', title: endpoint, description: `${String(ev.api || 'rest').toUpperCase()} request${ev.operation ? ` (${ev.operation})` : ''} on loopback-target returned HTTP ${ev.status_code}.`, status: 'SUCCESS', ts: ev.ts },
    { step: 4, phase: 'Loopback join', title: 'Request bound to SQL', description: `trace ${ev.trace_id} produced: ${queryTemplates.join(' | ') || 'no SQL'}.`, status: 'FLAGGED', ts: ev.ts },
    { step: 5, phase: 'Data traversal', title: `Touched ${tables.length ? tables.join(', ') : 'no tables'}`, description: `Target object reached: ${target}. Rows returned: ${queries.reduce((n, q) => n + (q.row_count || 0), 0)}.`, status: kind === 'IDOR' && ev.status_code === 200 ? 'FLAGGED' : 'SUCCESS', ts: ev.ts },
    { step: 6, phase: 'Detection', title: 'Loopback alert raised', description: `Sequence-level detector flagged this session activity — severity computed over the ${WINDOW_SECONDS}s window, not the single request.`, status: 'FLAGGED', ts: ev.ts },
  ];

  return { nodes, edges, steps };
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
  } else if (kind === 'HIJACK') {
    severity = 'HIGH';
  } else {
    severity = isCross || attempts >= 4 ? 'CRITICAL' : 'HIGH';
  }

  // Severity as a percentage (0–100): base by level, boosted by repetition and
  // cross-functional breadth — the UI renders this on a continuous green→red scale.
  const basePct = { INFO: 24, MEDIUM: 48, HIGH: 74, CRITICAL: 90 }[severity] ?? 50;
  const severityPct = Math.min(99, basePct + (isCross ? 4 : 0) + Math.min(5, (attempts - 1) * 2));

  const affected = [...new Set(windowEvs.map((w) => w.endpoint.split('?')[0]))].slice(-6);
  const attackPath = await buildAttackPath(ev, kind);

  const alert = {
    id: makeId(),
    ts: new Date().toISOString(),
    actorId: ev.actor_id,
    username: ev.username,
    alertType: kind === 'IDOR' ? 'POSSIBLE_IDOR_ATTACK'
      : kind === 'BIZLOGIC' ? 'POSSIBLE_BUSINESS_LOGIC_ATTACK'
      : kind === 'HIJACK' ? 'SUSPICIOUS_SESSION_ANOMALY'
      : 'RESOURCE_ENUMERATION_ATTACK',
    severity,
    severityPct,
    title,
    summary,
    attempts,
    isCrossFunctional: isCross,
    affectedEndpoints: affected,
    evidence: {
      traceId: ev.trace_id,
      sessionToken: ev.session_token || null,
      api: ev.api,
      operation: ev.operation,
      ip: ev.ip,
      userAgent: ev.user_agent,
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
  console.log(`[soc/correlate] ${severity} ${alert.alertType} (${severityPct}%) — ${ev.username} @ ${ev.endpoint}`);
  return alert;
}

/* ==========================================================================
   Detection entry point — called per ingested api event
   ========================================================================== */

export async function evaluateEvent(ev) {
  if (ev.actor_id == null) return []; // anonymous events (login failures etc.) — no session to correlate
  const windowEvs = await recentWindow(ev.actor_id, WINDOW_SECONDS);
  if (!windowEvs.length) return [];

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
    // Normal transfers are not enumeration — a client may legitimately pay
    // several beneficiaries in a minute. Business-logic rules cover transfers.
    if (cls === 'api/transfers' || cls === 'support') continue;
    if (targets.size >= 3) {
      flags.push({
        kind: 'ENUM',
        title: 'Resource Enumeration: Horizontal Sweep Detected',
        summary: `${ev.username} probed ${targets.size} distinct object targets on ${cls} within ${WINDOW_SECONDS}s (${[...targets].slice(0, 6).join(', ')}). Velocity exceeds any single-request baseline.`,
      });
      break; // one enumeration alert per event
    }
  }

  /* --- 4. Session hijack: one session token used from multiple IPs --------- */
  if (ev.session_token) {
    const ips = await distinctIpsForSession(ev.session_token);
    if (ips.length >= 2) {
      flags.push({
        kind: 'HIJACK',
        title: 'Session Hijack Suspected: Token Used From Multiple IPs',
        summary: `Session ${String(ev.session_token).slice(0, 12)}… (actor ${ev.username}) has been used from ${ips.length} different IPs within the hour (${ips.join(', ')}). Traffic was likely intercepted and the session token replayed from another machine.`,
      });
    }
  }

  const raised = [];
  for (const f of flags) {
    raised.push(await raiseAlert({ ev, kind: f.kind, title: f.title, summary: f.summary, windowEvs }));
  }
  return raised;
}
