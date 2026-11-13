/**
 * Loopback SOC — standalone security operations app.
 *
 * Receives API traffic (REST + GraphQL events) and tagged db events from the
 * vulnerable target, correlates them per session, runs the lightweight risk
 * engine, raises multi-step attack alerts, applies response actions (manual +
 * autonomous) to the target, and serves the operator console + REST/GraphQL.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import { createYoga, createSchema } from 'graphql-yoga';
import {
  ensureSchema, insertApiEvent, insertDbEvents,
  listAlerts, listEvents, listTrackedUsers, userActivity, userAlerts, userActions,
  stats, severityBreakdown, clearAll,
  listActions, getSettings, setSetting,
  latestRiskByActor, riskHistory, insertAction, setAlertResponse, validateOperator,
} from './db.js';
import { evaluateEvent } from './correlate.js';
import { updateRisk } from './risk.js';
import { maybeAutonomousResponse, applyAction } from './controls.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.SOC_PORT || 5100);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));

/* ==========================================================================
   Ingest — the target streams api_events + db_events here (fire-and-forget)
   ========================================================================== */

app.post('/ingest', async (req, res) => {
  const events = Array.isArray(req.body?.events) ? req.body.events : [];
  let apiCount = 0;
  let dbCount = 0;
  try {
    // SQL events first so the correlator can join api↔db on trace id
    for (const e of events) {
      if (e.kind === 'db') {
        await insertDbEvents([e]);
        dbCount++;
      }
    }
    const alertsRaised = [];
    const riskedActors = new Set();
    for (const e of events) {
      if (e.kind === 'api') {
        await insertApiEvent(e);
        apiCount++;
        // Normalize to the DB row shape the correlator reasons over
        const ev = {
          ts: e.ts,
          trace_id: e.traceId,
          actor_id: e.actorId ?? null,
          username: e.username ?? null,
          session_token: e.sessionToken ?? null,
          method: e.method,
          endpoint: e.endpoint,
          status_code: e.statusCode ?? 0,
          ip: e.ip ?? null,
          user_agent: e.userAgent ?? null,
          api: e.api ?? 'rest',
          operation: e.operation ?? null,
          params: e.params ?? null,
          resource_owner: e.resourceOwner ?? null,
          meta: e.meta ?? null,
        };
        alertsRaised.push(...(await evaluateEvent(ev))); // sequence-level correlation
        // Lightweight risk model per actor (throttled to once per ingest batch)
        if (ev.actor_id != null && !riskedActors.has(ev.actor_id)) {
          riskedActors.add(ev.actor_id);
          await updateRisk(ev.actor_id, ev.username);
        }
      }
    }
    // Autonomous response policy — risk engine + severity thresholds decide
    const autonomous = await maybeAutonomousResponse(alertsRaised);
    res.json({ success: true, ingested: apiCount + dbCount, api: apiCount, db: dbCount, alerts: alertsRaised.length, autonomous: autonomous.length });
  } catch (err) {
    console.error('[soc/ingest] error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ==========================================================================
   Operator authentication (lab default admin/admin — tracked like any login)
   ========================================================================== */

const operators = new Map(); // token -> {username, ip, ua, loginAt}
const OPERATOR_USERNAME = process.env.SOC_OPERATOR || 'admin';
const OPERATOR_PASSWORD = process.env.SOC_PASSWORD || 'admin';
let API_KEY = process.env.SOC_API_KEY || `lbk_${crypto.randomBytes(16).toString('hex')}`;

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '');
  const ua = String(req.headers['user-agent'] || 'unknown');
  const op = await validateOperator(username, password);
  if (op) {
    const token = crypto.randomBytes(16).toString('hex');
    operators.set(token, { username: op.username, name: op.name, role: op.role, ip, ua, loginAt: new Date().toISOString() });
    insertAction({
      kind: 'operator_login',
      targetValue: op.username,
      reason: `${op.name} (${op.role}) opened a session from ${ip} (${ua.slice(0, 60)})`,
      source: 'system',
      operator: op.name,
      alertId: null,
    }).catch(() => {});
    return res.json({
      success: true,
      token,
      role: op.role,
      username: op.username,
      name: op.name,
      loginFlow: ['credentials validated against the operator register', `operator session opened for ${op.name}`, 'login recorded in the audit log'],
    });
  }
  insertAction({
    kind: 'operator_login_failed',
    targetValue: String(username || 'unknown'),
    reason: `Failed operator login from ${ip} (${ua.slice(0, 60)})`,
    source: 'system',
    operator: String(username || 'unknown'),
    alertId: null,
  }).catch(() => {});
  res.status(401).json({ success: false, error: 'Invalid SOC credentials' });
});

function requireOperator(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  const key = req.headers['x-api-key'];
  if ((token && operators.has(token)) || (key && key === API_KEY)) {
    req.operator = token && operators.get(token) ? operators.get(token).name : 'api-key';
    return next();
  }
  return res.status(401).json({ success: false, error: 'Unauthorized SOC session' });
}

/* ==========================================================================
   Read APIs (operator console + integrations)
   ========================================================================== */

app.get('/api/health', (_req, res) => res.json({ success: true, status: 'ok' }));

app.get('/api/stats', requireOperator, async (_req, res) => {
  const [s, sev, acts] = await Promise.all([stats(), severityBreakdown(), import('./db.js').then((m) => m.countActionsToday())]);
  res.json({ success: true, stats: { ...s, actions_today: acts.total, autonomous_today: acts.autonomous }, severityBreakdown: sev });
});

app.get('/api/events', requireOperator, async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 300, 1000);
  res.json({ success: true, count: limit, events: await listEvents(limit) });
});

app.get('/api/alerts', requireOperator, async (req, res) => {
  res.json({ success: true, alerts: await listAlerts(200) });
});

app.get('/api/risk', requireOperator, async (_req, res) => {
  res.json({ success: true, risk: await latestRiskByActor() });
});

app.get('/api/risk/:actorId/history', requireOperator, async (req, res) => {
  res.json({ success: true, history: await riskHistory(Number(req.params.actorId)) });
});

/* ==========================================================================
   Tracked users — every actor: ID, IP, device, activity, risk, actions
   ========================================================================== */

app.get('/api/users', requireOperator, async (_req, res) => {
  const [users, risk, actions] = await Promise.all([
    listTrackedUsers(),
    latestRiskByActor(),
    import('./db.js').then((m) => m.activeControlsMap()),
  ]);
  const riskByActor = new Map(risk.map((r) => [r.actor_id, r]));
  res.json({
    success: true,
    count: users.length,
    users: users.map((u) => ({
      ...u,
      risk: u.risk ?? riskByActor.get(u.actor_id)?.score ?? 0,
      risk_level: riskByActor.get(u.actor_id)?.level ?? 'LOW',
    })),
  });
});

app.get('/api/users/:id', requireOperator, async (req, res) => {
  const actorId = Number(req.params.id);
  const [activity, alerts, actions, riskHist] = await Promise.all([
    userActivity(actorId),
    userAlerts(actorId),
    userActions(actorId),
    riskHistory(actorId),
  ]);
  const risk = (await latestRiskByActor()).find((r) => r.actor_id === actorId) || null;
  res.json({ success: true, actorId, risk, riskHistory: riskHist, activity, alerts, actions });
});

/* ==========================================================================
   Response actions — block user / revoke session / dismiss alert
   ========================================================================== */

app.get('/api/actions', requireOperator, async (_req, res) => {
  res.json({ success: true, actions: await listActions(200) });
});

app.post('/api/actions', requireOperator, async (req, res) => {
  const { kind, value, reason, alertId } = req.body || {};
  if (!kind || value == null) {
    return res.status(400).json({ success: false, error: 'kind and value are required' });
  }
  const valid = ['block_user', 'unblock_user', 'revoke_session', 'dismiss_alert'];
  if (!valid.includes(kind)) {
    return res.status(400).json({ success: false, error: `kind must be one of ${valid.join(', ')}` });
  }
  if (kind === 'dismiss_alert') {
    await setAlertResponse(String(value), {
      dismissed: true, by: req.operator, at: new Date().toISOString(),
    });
    const action = await insertAction({ kind, targetValue: String(value), reason: reason || 'Alert dismissed by operator', source: 'manual', operator: req.operator, alertId: String(value) });
    return res.json({ success: true, action });
  }
  const result = await applyAction({ kind, value, reason: reason || `${kind} by operator`, source: 'manual', operator: req.operator, alertId: alertId || null });
  if (kind === 'block_user' && alertId) {
    await setAlertResponse(String(alertId), { blocked: true, by: req.operator, at: new Date().toISOString() });
  }
  if (kind === 'revoke_session' && alertId) {
    await setAlertResponse(String(alertId), { sessionRevoked: true, by: req.operator, at: new Date().toISOString() });
  }
  res.json({ success: result.push.ok, action: result.action, push: result.push });
});

/* ==========================================================================
   Settings — autonomous response policy + thresholds + API key
   ========================================================================== */

app.get('/api/settings', requireOperator, async (req, res) => {
  res.json({ success: true, settings: await getSettings(), apiKey: API_KEY, operator: req.operator });
});

app.put('/api/settings', requireOperator, async (req, res) => {
  const allowed = ['auto_block_enabled', 'auto_block_severity', 'auto_revoke_enabled', 'auto_revoke_severity', 'risk_threshold', 'ingest_retention_hours'];
  for (const [key, value] of Object.entries(req.body || {})) {
    if (allowed.includes(key)) await setSetting(key, value);
  }
  res.json({ success: true, settings: await getSettings() });
});

app.post('/api/settings/apikey/rotate', requireOperator, (_req, res) => {
  API_KEY = `lbk_${crypto.randomBytes(16).toString('hex')}`;
  res.json({ success: true, apiKey: API_KEY });
});

app.post('/api/clear', requireOperator, async (_req, res) => {
  await clearAll();
  res.json({ success: true, message: 'SOC store cleared' });
});

/* ==========================================================================
   GraphQL read API — query alerts / events / sessions / users
   ========================================================================== */

const typeDefs = /* GraphQL */ `
  type Alert {
    id: String!
    ts: String!
    alertType: String!
    severity: String!
    title: String!
    summary: String!
    username: String
    attempts: Int!
    isCrossFunctional: Boolean!
    affectedEndpoints: String!
    attackPath: String!
    response: String!
  }
  type Event {
    id: String!
    ts: String!
    traceId: String!
    username: String
    ip: String
    method: String!
    endpoint: String!
    statusCode: Int!
    api: String!
    operation: String
    dbQueries: String!
  }
  type TrackedUser {
    actorId: Int!
    username: String
    apiEvents: Int!
    alerts: Int!
    risk: Int!
    riskLevel: String!
    lastSeen: String!
  }
  type Action {
    id: String!
    ts: String!
    kind: String!
    targetValue: String!
    reason: String
    source: String!
    operator: String
  }
  type Stats {
    apiEvents: Int!
    dbEvents: Int!
    alerts: Int!
    critical: Int!
    actors: Int!
    blockedUsers: Int!
    autonomousActions: Int!
  }
  type Query {
    alerts(severity: String, alertType: String, limit: Int): [Alert!]!
    events(api: String, limit: Int): [Event!]!
    users: [TrackedUser!]!
    actions(source: String, limit: Int): [Action!]!
    stats: Stats!
  }
`;

const resolvers = {
  Query: {
    alerts: async (_p, { severity, alertType, limit }) => {
      const rows = await listAlerts(Math.min(limit || 100, 500));
      return rows
        .filter((a) => (!severity || a.severity === severity) && (!alertType || a.alert_type === alertType))
        .map((a) => ({
          id: a.id,
          ts: new Date(a.ts).toISOString(),
          alertType: a.alert_type,
          severity: a.severity,
          title: a.title,
          summary: a.summary,
          username: a.username,
          attempts: a.attempts,
          isCrossFunctional: a.is_cross_functional,
          affectedEndpoints: JSON.stringify(a.affected_endpoints || []),
          attackPath: JSON.stringify(a.attack_path || {}),
          response: JSON.stringify(a.response || {}),
        }));
    },
    events: async (_p, { api, limit }) => {
      const rows = await listEvents(Math.min(limit || 100, 1000));
      return rows
        .filter((e) => !api || e.api === api)
        .map((e) => ({
          id: String(e.id),
          ts: new Date(e.ts).toISOString(),
          traceId: e.trace_id,
          username: e.username,
          ip: e.ip,
          method: e.method,
          endpoint: e.endpoint,
          statusCode: e.status_code,
          api: e.api,
          operation: e.operation,
          dbQueries: JSON.stringify(e.db_queries || []),
        }));
    },
    users: async () => {
      const { listTrackedUsers, latestRiskByActor } = await import('./db.js');
      const users = await listTrackedUsers();
      const risk = await latestRiskByActor();
      const byActor = new Map(risk.map((r) => [r.actor_id, r]));
      return users.map((u) => ({
        actorId: u.actor_id,
        username: u.username,
        apiEvents: u.api_events,
        alerts: u.alerts,
        risk: u.risk ?? byActor.get(u.actor_id)?.score ?? 0,
        riskLevel: byActor.get(u.actor_id)?.level ?? 'LOW',
        lastSeen: new Date(u.last_seen).toISOString(),
      }));
    },
    actions: async (_p, { source, limit }) => {
      const rows = await listActions(Math.min(limit || 100, 500));
      return rows
        .filter((a) => !source || a.source === source)
        .map((a) => ({
          id: String(a.id),
          ts: new Date(a.ts).toISOString(),
          kind: a.kind,
          targetValue: a.target_value,
          reason: a.reason,
          source: a.source,
          operator: a.operator,
        }));
    },
    stats: async () => {
      const s = await stats();
      return {
        apiEvents: s.api_events,
        dbEvents: s.db_events,
        alerts: s.alerts,
        critical: s.critical,
        actors: s.actors,
        blockedUsers: s.blocked_users,
        autonomousActions: s.autonomous_actions,
      };
    },
  },
};

const yoga = createYoga({
  schema: createSchema({ typeDefs, resolvers }),
  graphqlEndpoint: '/graphql',
  maskedErrors: false,
  landingPage: true,
});
app.use('/graphql', yoga);

/* ==========================================================================
   Operator console
   ========================================================================== */

app.use(express.static(path.join(__dirname, 'public'), { etag: false, lastModified: false, setHeaders: (res) => res.setHeader('Cache-Control', 'no-store') }));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

ensureSchema()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[Loopback SOC] console http://localhost:${PORT}  (GraphQL: /graphql, ingest: POST /ingest)`);
      console.log(`[Loopback SOC] response actions push to target at ${process.env.TARGET_URL || 'http://localhost:5000'}`);
    });
  })
  .catch((err) => {
    console.error('[Loopback SOC] failed to start:', err);
    process.exit(1);
  });
