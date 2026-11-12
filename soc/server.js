/**
 * Loopback SOC — standalone security operations app.
 *
 * Receives API traffic (REST + GraphQL events) and tagged db events from the
 * vulnerable target, correlates them per session, raises multi-step attack
 * alerts, and serves the operator console + a REST and GraphQL read API.
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
  listAlerts, listEvents, listSessions, actorTimeline, stats, clearAll,
} from './db.js';
import { evaluateEvent } from './correlate.js';

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
    // Insert SQL events first so the correlator can join api↔db on trace id
    for (const e of events) {
      if (e.kind === 'db') {
        await insertDbEvents([e]);
        dbCount++;
      }
    }
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
          api: e.api ?? 'rest',
          operation: e.operation ?? null,
          params: e.params ?? null,
          resource_owner: e.resourceOwner ?? null,
          meta: e.meta ?? null,
        };
        await evaluateEvent(ev); // sequence-level correlation runs per request
      }
    }
    res.json({ success: true, ingested: apiCount + dbCount, api: apiCount, db: dbCount });
  } catch (err) {
    console.error('[soc/ingest] error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ==========================================================================
   Operator auth (light gate: admin / admin — lab default)
   ========================================================================== */

const socTokens = new Set();

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === 'admin' && password === 'admin') {
    const token = crypto.randomBytes(16).toString('hex');
    socTokens.add(token);
    return res.json({ success: true, token, role: 'admin', username: 'admin' });
  }
  res.status(401).json({ success: false, error: 'Invalid SOC credentials' });
});

function requireSoc(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  if (!token || !socTokens.has(token)) {
    return res.status(401).json({ success: false, error: 'Unauthorized SOC session' });
  }
  next();
}

/* ==========================================================================
   REST read API (operator console + integrations)
   ========================================================================== */

app.get('/api/health', async (_req, res) => {
  try {
    res.json({ success: true, status: 'ok' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/events', requireSoc, async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 300, 1000);
  res.json({ success: true, count: limit, events: await listEvents(limit) });
});

app.get('/api/alerts', requireSoc, async (req, res) => {
  res.json({ success: true, alerts: await listAlerts(200) });
});

app.get('/api/sessions', requireSoc, async (req, res) => {
  res.json({ success: true, sessions: await listSessions(60) });
});

app.get('/api/sessions/:actorId/timeline', requireSoc, async (req, res) => {
  res.json({ success: true, timeline: await actorTimeline(Number(req.params.actorId), 120) });
});

app.get('/api/stats', requireSoc, async (_req, res) => {
  res.json({ success: true, stats: await stats() });
});

app.post('/api/clear', requireSoc, async (_req, res) => {
  await clearAll();
  res.json({ success: true, message: 'SOC store cleared' });
});

/* ==========================================================================
   GraphQL read API — query alerts / events / sessions programmatically
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
  }
  type Event {
    id: String!
    ts: String!
    traceId: String!
    username: String
    method: String!
    endpoint: String!
    statusCode: Int!
    api: String!
    operation: String
    dbQueries: String!
  }
  type Session {
    username: String!
    actorId: Int!
    apiEvents: Int!
    lastSeen: String!
    distinctEndpoints: Int!
  }
  type Stats {
    apiEvents: Int!
    dbEvents: Int!
    alerts: Int!
    critical: Int!
    actors: Int!
  }
  type Query {
    alerts(severity: String, limit: Int): [Alert!]!
    events(api: String, limit: Int): [Event!]!
    sessions: [Session!]!
    stats: Stats!
  }
`;

const resolvers = {
  Query: {
    alerts: async (_p, { severity, limit }) => {
      const rows = await listAlerts(Math.min(limit || 100, 500));
      return rows
        .filter((a) => !severity || a.severity === severity)
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
          method: e.method,
          endpoint: e.endpoint,
          statusCode: e.status_code,
          api: e.api,
          operation: e.operation,
          dbQueries: JSON.stringify(e.db_queries || []),
        }));
    },
    sessions: async () => {
      const rows = await listSessions(60);
      return rows.map((s) => ({
        username: s.username,
        actorId: s.actor_id,
        apiEvents: s.api_events,
        lastSeen: new Date(s.last_seen).toISOString(),
        distinctEndpoints: s.distinct_endpoints,
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

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

ensureSchema()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[Loopback SOC] console http://localhost:${PORT}  (GraphQL: /graphql, ingest: POST /ingest)`);
    });
  })
  .catch((err) => {
    console.error('[Loopback SOC] failed to start:', err);
    process.exit(1);
  });
