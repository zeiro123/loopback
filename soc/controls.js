/**
 * Loopback SOC — response control plane (SOC side).
 *
 * Applies response actions to the vulnerable target: pushes block/revoke
 * commands to the target's control endpoint, logs every action (manual or
 * autonomous), and evaluates the autonomous-response policy after each alert.
 */
import { insertAction, getSettings, latestRiskByActor } from './db.js';

const TARGET_URL = process.env.TARGET_URL || 'http://localhost:5000';
const SOC_CONTROL_KEY = process.env.SOC_CONTROL_KEY || 'loopback-soc-key';

const SEVERITY_RANK = { INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

async function pushToTarget(kind, value, reason, source, durationMs = null) {
  try {
    const res = await fetch(`${TARGET_URL}/api/soc/controls`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-soc-key': SOC_CONTROL_KEY },
      body: JSON.stringify({ kind, value: String(value), reason, source, ...(durationMs ? { durationMs } : {}) }),
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, data };
  } catch (err) {
    console.error(`[soc/controls] push failed (${kind} ${value}): ${err.message}`);
    return { ok: false, error: err.message };
  }
}

/**
 * Apply a response action: push it to the target and record it.
 */
export async function applyAction({ kind, value, reason, source = 'manual', operator = null, alertId = null, durationMs = null }) {
  const expiresAt = Number(durationMs) > 0 ? new Date(Date.now() + Number(durationMs)).toISOString() : null;
  const push = await pushToTarget(kind, value, reason, source, expiresAt ? Number(durationMs) : null);
  const action = await insertAction({
    kind, targetValue: String(value), reason, source, operator, alertId, expiresAt,
  });
  return { action, push };
}

/**
 * Autonomous response policy — the "AI makes an informed decision" step.
 *
 * After every raised alert, the risk engine's score decides whether to act:
 *   1. severity rule  — alert severity ≥ configured threshold (default CRITICAL)
 *      → block the user and revoke their live sessions.
 *   2. risk rule      — the lightweight statistical model scores the user
 *      ≥ risk_threshold (default 75) → block regardless of single-alert severity.
 *
 * Every autonomous action is logged with its reason (alert id, risk score and
 * the feature contributions that drove it) so the operator can audit the model.
 */
export async function maybeAutonomousResponse(alertsRaised) {
  if (!alertsRaised?.length) return [];
  const settings = await getSettings();
  const applied = [];

  // Latest risk per actor involved
  const riskRows = await latestRiskByActor();
  const riskByActor = new Map(riskRows.map((r) => [r.actor_id, r]));

  for (const alert of alertsRaised) {
    const actorId = alert.actorId ?? alert.actor_id;
    if (actorId == null) continue;

    // Already blocked in this batch? Skip duplicates.
    if (applied.some((a) => a.kind === 'block_user' && a.targetValue === String(actorId))) continue;

    const risk = riskByActor.get(actorId);
    const riskScore = risk?.score ?? 0;
    const sevRank = SEVERITY_RANK[alert.severity] ?? 0;
    const sevThreshold = SEVERITY_RANK[settings.auto_block_severity] ?? 3;
    const reasons = [];

    if (settings.auto_block_enabled && sevRank >= sevThreshold) {
      reasons.push(`alert severity ${alert.severity} ≥ threshold ${settings.auto_block_severity}`);
    }
    if (settings.auto_revoke_enabled && sevRank >= (SEVERITY_RANK[settings.auto_revoke_severity] ?? 3)) {
      reasons.push(`session revocation policy met (severity ${alert.severity})`);
    }
    if (riskScore >= Number(settings.risk_threshold || 75)) {
      reasons.push(`risk engine score ${riskScore} ≥ threshold ${settings.risk_threshold}`);
    }

    if (!reasons.length) continue;

    const reasonText = `Autonomous response: ${reasons.join('; ')}. Trigger: ${alert.alert_type} (${alert.severity}) — ${alert.title}. Trace ${alert.evidence?.traceId || 'n/a'}.`;

    const block = await applyAction({
      kind: 'block_user',
      value: actorId,
      reason: reasonText,
      source: 'autonomous',
      operator: 'risk-engine',
      alertId: alert.id,
    });
    applied.push({ kind: 'block_user', targetValue: String(actorId), ok: block.push.ok, action: block.action });
    console.log(`[soc/controls] AUTONOMOUS block_user ${actorId} — ${reasons.join('; ')}`);

    if (settings.auto_revoke_enabled) {
      const token = alert.evidence?.sessionToken || alert.evidence?.session_token;
      if (token) {
        const revoke = await applyAction({
          kind: 'revoke_session',
          value: token,
          reason: `Autonomous response: session of blocked user ${actorId} revoked (${reasons.join('; ')})`,
          source: 'autonomous',
          operator: 'risk-engine',
          alertId: alert.id,
        });
        applied.push({ kind: 'revoke_session', targetValue: String(token).slice(0, 12) + '…', ok: revoke.push.ok, action: revoke.action });
      }
    }
  }
  return applied;
}
