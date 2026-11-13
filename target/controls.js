/**
 * Apex Trust Bank — SOC control plane (target side).
 *
 * The Loopback SOC applies response actions (block user / revoke session) by
 * calling these endpoints. The shared key keeps the control channel closed to
 * the operator. Enforcement also happens on every request: the auth middleware
 * checks the blocklist / revocation list on each call.
 */
import { applyControl, deactivateControl, activeControls } from './db.js';

export const SOC_CONTROL_KEY = process.env.SOC_CONTROL_KEY || 'loopback-soc-key';

export function requireSocKey(req, res) {
  const key = req.headers['x-soc-key'];
  if (key !== SOC_CONTROL_KEY) {
    res.status(403).json({ success: false, error: 'Invalid SOC control key' });
    return false;
  }
  return true;
}

export async function handleControl(req, res) {
  if (!requireSocKey(req, res)) return;
  const { kind, value, reason, source } = req.body || {};
  if (!kind || value == null) {
    return res.status(400).json({ success: false, error: 'kind and value are required' });
  }
  if (kind === 'unblock_user') {
    const n = await deactivateControl('block_user', String(value));
    return res.json({ success: true, applied: `unblock_user:${value}`, deactivated: n });
  }
  if (kind === 'unrevoke_session') {
    const n = await deactivateControl('revoke_session', String(value));
    return res.json({ success: true, applied: `unrevoke_session:${value}`, deactivated: n });
  }
  if (!['block_user', 'revoke_session'].includes(kind)) {
    return res.status(400).json({ success: false, error: `unknown control kind: ${kind}` });
  }
  const control = await applyControl({ kind, value: String(value), reason, source: source || 'manual' });
  console.log(`[target/soc-control] ${kind} ${value} (${source || 'manual'})`);
  res.json({ success: true, control });
}

export async function handleControlPoll(_req, res) {
  res.json({ success: true, controls: await activeControls() });
}
