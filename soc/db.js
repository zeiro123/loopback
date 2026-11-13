/**
 * Loopback SOC — event store (PostgreSQL).
 *
 * Holds the raw api_events + db_events streams (with trace ids, IPs and
 * devices), the correlation engine's alerts, every response action (manual +
 * autonomous), per-user risk history, and operator settings.
 */
import { Pool } from 'pg';

const SOC_DATABASE_URL =
  process.env.SOC_DATABASE_URL || 'postgres://postgres:12345678@localhost:5432/soc';

export const pool = new Pool({ connectionString: SOC_DATABASE_URL });

export async function ensureSchema() {
  const ddl = [
    `CREATE TABLE IF NOT EXISTS api_events (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      trace_id TEXT NOT NULL,
      actor_id INTEGER,
      username TEXT,
      session_token TEXT,
      method TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      status_code INTEGER NOT NULL,
      ip TEXT,
      user_agent TEXT,
      api TEXT NOT NULL DEFAULT 'rest',
      operation TEXT,
      params JSONB,
      resource_owner JSONB,
      meta JSONB,
      duration_ms INTEGER
    )`,
    `CREATE INDEX IF NOT EXISTS api_events_ts_idx ON api_events (ts DESC)`,
    `CREATE INDEX IF NOT EXISTS api_events_actor_idx ON api_events (actor_id, ts DESC)`,
    `CREATE INDEX IF NOT EXISTS api_events_trace_idx ON api_events (trace_id)`,
    `CREATE TABLE IF NOT EXISTS db_events (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      trace_id TEXT NOT NULL,
      actor_id INTEGER,
      username TEXT,
      query TEXT,
      template TEXT,
      row_count INTEGER
    )`,
    `CREATE INDEX IF NOT EXISTS db_events_trace_idx ON db_events (trace_id)`,
    `CREATE INDEX IF NOT EXISTS db_events_ts_idx ON db_events (ts DESC)`,
    `CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      actor_id INTEGER,
      username TEXT,
      alert_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 1,
      is_cross_functional BOOLEAN NOT NULL DEFAULT false,
      affected_endpoints JSONB NOT NULL DEFAULT '[]'::jsonb,
      evidence JSONB,
      attack_path JSONB,
      response JSONB NOT NULL DEFAULT '{}'::jsonb
    )`,
    `CREATE INDEX IF NOT EXISTS alerts_ts_idx ON alerts (ts DESC)`,
    `CREATE TABLE IF NOT EXISTS soc_actions (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      kind TEXT NOT NULL,
      target_value TEXT NOT NULL,
      reason TEXT,
      source TEXT NOT NULL DEFAULT 'manual',
      operator TEXT,
      alert_id TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS user_risk (
      id BIGSERIAL PRIMARY KEY,
      actor_id INTEGER NOT NULL,
      username TEXT,
      ts TIMESTAMPTZ NOT NULL DEFAULT now(),
      score INTEGER NOT NULL,
      level TEXT NOT NULL,
      features JSONB
    )`,
    `CREATE INDEX IF NOT EXISTS user_risk_actor_idx ON user_risk (actor_id, ts DESC)`,
    `CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL
    )`,
    `ALTER TABLE alerts ADD COLUMN IF NOT EXISTS response JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `ALTER TABLE api_events ADD COLUMN IF NOT EXISTS user_agent TEXT`,
  ];
  for (let attempt = 1; attempt <= 25; attempt++) {
    try {
      for (const stmt of ddl) await pool.query(stmt);
      await seedSettings();
      return;
    } catch (err) {
      if (attempt === 25) throw err;
      console.error(`[soc/db] schema attempt ${attempt} failed: ${err.message} — retrying`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

const DEFAULT_SETTINGS = {
  auto_block_enabled: true,
  auto_block_severity: 'CRITICAL',
  auto_revoke_enabled: true,
  auto_revoke_severity: 'CRITICAL',
  risk_threshold: 75,
  ingest_retention_hours: 72,
};

async function seedSettings() {
  for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
    await pool.query('INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO NOTHING', [key, JSON.stringify(value)]);
  }
}

export async function getSettings() {
  const { rows } = await pool.query('SELECT key, value FROM settings');
  const out = { ...DEFAULT_SETTINGS };
  for (const r of rows) out[r.key] = typeof r.value === 'string' ? r.value.replace(/^"|"$/g, '') : r.value;
  return out;
}

export async function setSetting(key, value) {
  await pool.query(
    'INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value = $2',
    [key, JSON.stringify(value)]
  );
}

/* ==========================================================================
   Ingest
   ========================================================================== */

export async function insertApiEvent(e) {
  const { rows } = await pool.query(
    `INSERT INTO api_events (ts, trace_id, actor_id, username, session_token, method, endpoint,
       status_code, ip, user_agent, api, operation, params, resource_owner, meta, duration_ms)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id, ts`,
    [
      e.ts || new Date().toISOString(), e.traceId, e.actorId ?? null, e.username ?? null,
      e.sessionToken ?? null, e.method, e.endpoint, e.statusCode ?? 0, e.ip ?? null,
      e.userAgent ?? null, e.api ?? 'rest', e.operation ?? null, JSON.stringify(e.params ?? null),
      JSON.stringify(e.resourceOwner ?? null), JSON.stringify(e.meta ?? null),
      e.durationMs ?? null,
    ]
  );
  return rows[0];
}

export async function insertDbEvents(events) {
  for (const e of events) {
    await pool.query(
      `INSERT INTO db_events (ts, trace_id, actor_id, username, query, template, row_count)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [e.ts || new Date().toISOString(), e.traceId, e.actorId ?? null, e.username ?? null,
       e.query ?? null, e.template ?? null, e.rowCount ?? 0]
    );
  }
}

export async function recentWindow(actorId, seconds = 60) {
  const { rows } = await pool.query(
    `SELECT id, ts, trace_id, actor_id, username, session_token, method, endpoint, status_code,
            ip, user_agent, api, operation, params, resource_owner, meta
     FROM api_events
     WHERE actor_id = $1 AND ts > now() - ($2 || ' seconds')::interval
     ORDER BY ts ASC`,
    [actorId, String(seconds)]
  );
  return rows;
}

export async function dbEventsForTrace(traceId) {
  const { rows } = await pool.query(
    `SELECT ts, trace_id, query, template, row_count FROM db_events WHERE trace_id = $1 ORDER BY ts ASC`,
    [traceId]
  );
  return rows;
}

export async function countRecentAlerts(actorId, alertType, minutes = 10) {
  const { rows } = await pool.query(
    `SELECT COUNT(*)::int AS n FROM alerts
     WHERE actor_id = $1 AND alert_type = $2 AND ts > now() - ($3 || ' minutes')::interval`,
    [actorId, alertType, String(minutes)]
  );
  return rows[0].n;
}

export async function insertAlert(alert) {
  await pool.query(
    `INSERT INTO alerts (id, ts, actor_id, username, alert_type, severity, title, summary,
        attempts, is_cross_functional, affected_endpoints, evidence, attack_path)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     ON CONFLICT (id) DO NOTHING`,
    [
      alert.id, alert.ts, alert.actorId ?? null, alert.username ?? null, alert.alertType,
      alert.severity, alert.title, alert.summary, alert.attempts ?? 1,
      alert.isCrossFunctional ?? false, JSON.stringify(alert.affectedEndpoints ?? []),
      JSON.stringify(alert.evidence ?? null), JSON.stringify(alert.attackPath ?? null),
    ]
  );
}

export async function setAlertResponse(alertId, response) {
  await pool.query('UPDATE alerts SET response = $2 WHERE id = $1', [alertId, JSON.stringify(response)]);
}

/* ==========================================================================
   Response actions (manual + autonomous)
   ========================================================================== */

export async function insertAction({ kind, targetValue, reason, source, operator, alertId }) {
  const { rows } = await pool.query(
    `INSERT INTO soc_actions (kind, target_value, reason, source, operator, alert_id)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, ts`,
    [kind, String(targetValue), reason ?? null, source || 'manual', operator ?? null, alertId ?? null]
  );
  return rows[0];
}

export async function listActions(limit = 200) {
  const { rows } = await pool.query(
    'SELECT * FROM soc_actions ORDER BY ts DESC LIMIT $1',
    [limit]
  );
  return rows;
}

export async function countActionsToday() {
  const { rows } = await pool.query(
    `SELECT
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE source = 'autonomous')::int AS autonomous,
       COUNT(*) FILTER (WHERE kind = 'block_user' AND ts > now() - interval '24 hours')::int AS blocks_24h
     FROM soc_actions`
  );
  return rows[0];
}

/* ==========================================================================
   Risk (lightweight statistical model)
   ========================================================================== */

export async function saveRisk(actorId, username, score, level, features) {
  await pool.query(
    'INSERT INTO user_risk (actor_id, username, score, level, features) VALUES ($1,$2,$3,$4,$5)',
    [actorId, username ?? null, score, level, JSON.stringify(features)]
  );
}

export async function latestRiskByActor() {
  const { rows } = await pool.query(
    `SELECT DISTINCT ON (actor_id) actor_id, username, score, level, features, ts
     FROM user_risk ORDER BY actor_id, ts DESC`
  );
  return rows;
}

export async function riskHistory(actorId, limit = 40) {
  const { rows } = await pool.query(
    'SELECT ts, score, level FROM user_risk WHERE actor_id = $1 ORDER BY ts DESC LIMIT $2',
    [actorId, limit]
  );
  return rows.reverse();
}

export async function activeControlsMap() {
  const { rows } = await pool.query(
    "SELECT DISTINCT kind, target_value FROM soc_actions WHERE kind IN ('block_user','revoke_session') AND ts > now() - interval '24 hours'"
  );
  return rows;
}

/* ==========================================================================
   Read APIs for the SOC console
   ========================================================================== */

export async function listAlerts(limit = 200) {
  const { rows } = await pool.query(
    `SELECT id, ts, actor_id, username, alert_type, severity, title, summary, attempts,
            is_cross_functional, affected_endpoints, evidence, attack_path, response
     FROM alerts ORDER BY ts DESC LIMIT $1`,
    [limit]
  );
  return rows;
}

export async function listEvents(limit = 300) {
  const { rows } = await pool.query(
    `SELECT a.id, a.ts, a.trace_id, a.actor_id, a.username, a.method, a.endpoint, a.status_code,
            a.ip, a.user_agent, a.api, a.operation, a.params, a.resource_owner, a.meta, a.duration_ms,
            COALESCE(
              (SELECT json_agg(json_build_object('ts', d.ts, 'template', d.template,
                                                 'query', d.query, 'rowCount', d.row_count)
                        ORDER BY d.ts)
                 FROM db_events d WHERE d.trace_id = a.trace_id),
              '[]'::json
            ) AS db_queries
     FROM api_events a
     ORDER BY a.ts DESC LIMIT $1`,
    [limit]
  );
  return rows;
}

export async function listTrackedUsers(minutes = 24 * 60) {
  const { rows } = await pool.query(
    `SELECT u.actor_id,
            MAX(u.username) AS username,
            COUNT(*)::int AS api_events,
            COUNT(DISTINCT split_part(u.endpoint, '?', 1))::int AS distinct_endpoints,
            MAX(u.ts) AS last_seen,
            MIN(u.ts) AS first_seen,
            (SELECT COUNT(*)::int FROM api_events e2 WHERE e2.actor_id = u.actor_id
                AND e2.status_code >= 400) AS errors,
            COALESCE(
              (SELECT json_agg(DISTINCT u.ip) FROM api_events u WHERE u.actor_id IS NOT NULL AND u.ip IS NOT NULL),
              '[]'::json
            ) AS ips,
            COALESCE(
              (SELECT json_agg(json_build_object('ip', d.ip, 'ua', d.user_agent))
                 FROM (SELECT ip, user_agent FROM api_events WHERE actor_id = u.actor_id GROUP BY ip, user_agent LIMIT 5) d),
              '[]'::json
            ) AS devices,
            (SELECT COUNT(*)::int FROM alerts a WHERE a.actor_id = u.actor_id) AS alerts,
            (SELECT MAX(score)::int FROM user_risk r WHERE r.actor_id = u.actor_id
                AND r.ts > now() - interval '30 minutes') AS risk
     FROM api_events u
     WHERE u.actor_id IS NOT NULL AND u.ts > now() - ($1 || ' minutes')::interval
     GROUP BY u.actor_id
     ORDER BY last_seen DESC`,
    [String(minutes)]
  );
  return rows;
}

export async function userActivity(actorId, limit = 200) {
  const { rows } = await pool.query(
    `SELECT a.id, a.ts, a.trace_id, a.actor_id, a.username, a.method, a.endpoint, a.status_code,
            a.ip, a.user_agent, a.api, a.operation, a.params, a.resource_owner, a.meta,
            COALESCE(
              (SELECT json_agg(json_build_object('ts', d.ts, 'template', d.template,
                                                 'query', d.query, 'rowCount', d.row_count)
                        ORDER BY d.ts)
                 FROM db_events d WHERE d.trace_id = a.trace_id),
              '[]'::json
            ) AS db_queries
     FROM api_events a
     WHERE a.actor_id = $1
     ORDER BY a.ts DESC LIMIT $2`,
    [actorId, limit]
  );
  return rows;
}

export async function userAlerts(actorId, limit = 50) {
  const { rows } = await pool.query(
    `SELECT id, ts, alert_type, severity, title, summary, response FROM alerts
     WHERE actor_id = $1 ORDER BY ts DESC LIMIT $2`,
    [actorId, limit]
  );
  return rows;
}

export async function userActions(actorId, limit = 50) {
  const { rows } = await pool.query(
    `SELECT * FROM soc_actions WHERE target_value = $1 OR target_value = $2
     ORDER BY ts DESC LIMIT $3`,
    [String(actorId), String(actorId), limit]
  );
  return rows;
}

export async function stats() {
  const { rows } = await pool.query(`
    SELECT
      (SELECT COUNT(*)::int FROM api_events) AS api_events,
      (SELECT COUNT(*)::int FROM db_events) AS db_events,
      (SELECT COUNT(*)::int FROM alerts) AS alerts,
      (SELECT COUNT(*)::int FROM alerts WHERE severity IN ('HIGH','CRITICAL')) AS critical,
      (SELECT COUNT(DISTINCT actor_id)::int FROM api_events WHERE actor_id IS NOT NULL) AS actors,
      (SELECT COUNT(*)::int FROM soc_actions WHERE kind = 'block_user' AND ts > now() - interval '24 hours') AS blocked_users,
      (SELECT COUNT(*)::int FROM soc_actions WHERE source = 'autonomous') AS autonomous_actions,
      (SELECT COALESCE(AVG(score), 0)::int FROM user_risk r
         WHERE r.ts > now() - interval '30 minutes'
         AND r.ts = (SELECT MAX(ts) FROM user_risk r2 WHERE r2.actor_id = r.actor_id)) AS avg_risk
  `);
  return rows[0];
}

export async function severityBreakdown() {
  const { rows } = await pool.query(
    `SELECT severity, COUNT(*)::int AS n FROM alerts GROUP BY severity`
  );
  return rows;
}

export async function clearAll() {
  await pool.query('TRUNCATE api_events, db_events, alerts, soc_actions, user_risk');
}
