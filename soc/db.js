/**
 * Loopback SOC — event store (PostgreSQL).
 *
 * Holds the raw api_events + db_events streams (with trace ids), the
 * correlation engine's alerts, and aggregation queries for the SOC UI.
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
      attack_path JSONB
    )`,
    `CREATE INDEX IF NOT EXISTS alerts_ts_idx ON alerts (ts DESC)`,
  ];
  for (let attempt = 1; attempt <= 25; attempt++) {
    try {
      for (const stmt of ddl) await pool.query(stmt);
      return;
    } catch (err) {
      if (attempt === 25) throw err;
      console.error(`[soc/db] schema attempt ${attempt} failed: ${err.message} — retrying`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

export async function insertApiEvent(e) {
  const { rows } = await pool.query(
    `INSERT INTO api_events (ts, trace_id, actor_id, username, session_token, method, endpoint,
       status_code, ip, api, operation, params, resource_owner, meta, duration_ms)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id, ts`,
    [
      e.ts || new Date().toISOString(), e.traceId, e.actorId ?? null, e.username ?? null,
      e.sessionToken ?? null, e.method, e.endpoint, e.statusCode ?? 0, e.ip ?? null,
      e.api ?? 'rest', e.operation ?? null, JSON.stringify(e.params ?? null),
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

/* ==========================================================================
   Correlation queries
   ========================================================================== */

export async function recentWindow(actorId, seconds = 60) {
  const { rows } = await pool.query(
    `SELECT id, ts, trace_id, actor_id, username, method, endpoint, status_code, api, operation,
            params, resource_owner, meta
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

/* ==========================================================================
   Read APIs for the SOC console
   ========================================================================== */

export async function listAlerts(limit = 200) {
  const { rows } = await pool.query(
    `SELECT id, ts, actor_id, username, alert_type, severity, title, summary, attempts,
            is_cross_functional, affected_endpoints, evidence, attack_path
     FROM alerts ORDER BY ts DESC LIMIT $1`,
    [limit]
  );
  return rows;
}

export async function listEvents(limit = 300) {
  // Merged stream: api events with their db queries nested (the loopback chain).
  const { rows } = await pool.query(
    `SELECT a.id, a.ts, a.trace_id, a.actor_id, a.username, a.method, a.endpoint, a.status_code,
            a.ip, a.api, a.operation, a.params, a.resource_owner, a.meta, a.duration_ms,
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

export async function listSessions(minutes = 60) {
  const { rows } = await pool.query(
    `SELECT username, actor_id,
            COUNT(*)::int AS api_events,
            MAX(ts) AS last_seen,
            COUNT(DISTINCT split_part(endpoint, '?', 1))::int AS distinct_endpoints
     FROM api_events
     WHERE actor_id IS NOT NULL AND ts > now() - ($1 || ' minutes')::interval
     GROUP BY username, actor_id
     ORDER BY last_seen DESC`,
    [String(minutes)]
  );
  return rows;
}

export async function actorTimeline(actorId, limit = 120) {
  const { rows } = await pool.query(
    `SELECT a.id, a.ts, a.trace_id, a.actor_id, a.username, a.method, a.endpoint, a.status_code,
            a.api, a.operation, a.params, a.resource_owner, a.meta,
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

export async function stats() {
  const { rows } = await pool.query(`
    SELECT
      (SELECT COUNT(*)::int FROM api_events) AS api_events,
      (SELECT COUNT(*)::int FROM db_events) AS db_events,
      (SELECT COUNT(*)::int FROM alerts) AS alerts,
      (SELECT COUNT(*)::int FROM alerts WHERE severity IN ('HIGH','CRITICAL')) AS critical,
      (SELECT COUNT(DISTINCT actor_id)::int FROM api_events WHERE actor_id IS NOT NULL) AS actors
  `);
  return rows[0];
}

export async function clearAll() {
  await pool.query('TRUNCATE api_events, db_events, alerts');
}
