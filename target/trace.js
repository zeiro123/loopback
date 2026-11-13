/**
 * Trace-injection middleware — the "loopback" starts here.
 *
 * Every request (REST or GraphQL) gets a trace id. The id rides out on the
 * response header, is stamped into every SQL comment, and the finished request
 * plus its captured db events are forwarded to the Loopback SOC engine for
 * correlation.
 */
import { AsyncLocalStorage } from 'async_hooks';
import crypto from 'crypto';

export const als = new AsyncLocalStorage();

const SOC_URL = process.env.SOC_URL || 'http://localhost:5100';

export function traceMiddleware(req, res, next) {
  const traceId = crypto.randomUUID();
  const store = {
    traceId,
    method: req.method,
    endpoint: req.originalUrl.split('?')[0],
    api: req.originalUrl.startsWith('/graphql') ? 'graphql' : 'rest',
    operation: null,
    actorId: null,
    username: null,
    sessionToken: null,
    ip: String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || ''),
    userAgent: String(req.headers['user-agent'] || 'unknown'),
    params: null,
    resourceOwner: null,
    meta: null,
    dbEvents: [],
    startedAt: Date.now(),
  };
  res.setHeader('X-Trace-Id', traceId);

  als.run(store, () => {
    res.on('finish', () => {
      try {
        flush(store, res);
      } catch {
        /* never break the banking response over telemetry */
      }
    });
    next();
  });
}

export function setActor(user, token) {
  const s = als.getStore();
  if (s && user) {
    s.actorId = user.id;
    s.username = user.username;
    s.sessionToken = token || null;
  }
}

export function setParams(p) {
  const s = als.getStore();
  if (s) s.params = p ?? null;
}

export function setResourceOwner(o) {
  const s = als.getStore();
  if (s) s.resourceOwner = o ?? null;
}

export function setMeta(m) {
  const s = als.getStore();
  if (s) s.meta = m ?? null;
}

export function setOperation(op) {
  const s = als.getStore();
  if (s) s.operation = op ?? null;
}

function flush(store, res) {
  const apiEvent = {
    kind: 'api',
    ts: new Date().toISOString(),
    traceId: store.traceId,
    actorId: store.actorId ?? null,
    username: store.username ?? null,
    sessionToken: store.sessionToken ?? null,
    method: store.method,
    endpoint: store.endpoint,
    statusCode: res.statusCode,
    ip: store.ip,
    userAgent: store.userAgent,
    api: store.api,
    operation: store.operation,
    params: store.params,
    resourceOwner: store.resourceOwner,
    meta: store.meta,
    durationMs: Date.now() - store.startedAt,
  };
  const events = [apiEvent, ...store.dbEvents];
  fetch(`${SOC_URL}/ingest`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ events }),
  }).catch(() => {
    /* SOC unavailable — banking keeps running, telemetry is best-effort */
  });
}
