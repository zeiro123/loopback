/**
 * Loopback Risk Engine — lightweight statistical user-risk model.
 *
 * Proof of concept for the AI-assisted detection component: a transparent,
 * explainable scoring model over each actor's recent behaviour. No black box —
 * every score decomposes into named feature contributions the operator can
 * read. The dissertation's sub-2B LLM classifier will later be compared
 * against this baseline.
 *
 * Features (per actor, over a sliding 10-minute window):
 *   velocity        — requests/minute vs a 30 req/min baseline
 *   target_breadth  — distinct object targets touched (enumeration signal)
 *   idor_hits       — confirmed IDOR/BOLA events (owner ≠ actor)
 *   bizlogic_hits   — ledger-invariant violations
 *   error_rate      — share of 4xx/5xx responses (probing / fuzzing signal)
 *   cross_functional— how many distinct endpoint classes the actor touched
 *   data_volume     — rows returned by the SQL the actor's traces produced
 */
import { recentWindow, saveRisk } from './db.js';

const FEATURES = [
  { name: 'velocity', weight: 15, max: 60, describe: 'requests/min vs 30/min baseline' },
  { name: 'target_breadth', weight: 15, max: 12, describe: 'distinct object targets touched' },
  { name: 'idor_hits', weight: 20, max: 4, describe: 'confirmed IDOR / BOLA events' },
  { name: 'bizlogic_hits', weight: 20, max: 3, describe: 'ledger-invariant violations' },
  { name: 'error_rate', weight: 10, max: 10, describe: 'share of 4xx/5xx responses (%)' },
  { name: 'cross_functional', weight: 10, max: 5, describe: 'distinct endpoint classes touched' },
  { name: 'data_volume', weight: 10, max: 400, describe: 'rows returned by traced SQL' },
];

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

export function extractFeatures(windowEvents, dbRowsByTrace = 0) {
  const now = Date.now();
  const tenMin = windowEvents.filter((e) => now - new Date(e.ts).getTime() <= 10 * 60 * 1000);
  const minutes = Math.max(1 / 60, (10 * 60 * 1000) / (10 * 60 * 1000)) * (tenMin.length ? 1 : 0);

  const velocity = clamp(tenMin.length / 10, 0, 60); // requests per minute over the window
  const targets = new Set();
  let idor = 0;
  let bizlogic = 0;
  const classes = new Set();
  let errors = 0;

  for (const e of tenMin) {
    const ro = e.resource_owner || {};
    const meta = e.meta || {};
    if (ro.accountNumber) targets.add(`acc:${ro.accountNumber}`);
    else if (ro.userId != null) targets.add(`user:${ro.userId}`);
    else if (meta.toAccountNumber) targets.add(`acc:${meta.toAccountNumber}`);
    if (ro.userId != null && e.actor_id != null && Number(ro.userId) !== Number(e.actor_id)) idor++;
    if (meta.amount != null && String(e.endpoint).includes('transfers') && Number(meta.amount) <= 0) bizlogic++;
    if (meta.amount != null && String(e.endpoint).includes('transfers') && meta.balanceBefore != null && Number(meta.amount) > Number(meta.balanceBefore)) bizlogic++;
    classes.add(String(e.endpoint).split('/').slice(1, 3).join('/'));
    if (e.status_code >= 400) errors++;
  }

  const features = {
    velocity: Math.round(velocity * 10) / 10,
    target_breadth: targets.size,
    idor_hits: idor,
    bizlogic_hits: bizlogic,
    error_rate: tenMin.length ? Math.round((errors / tenMin.length) * 100) : 0,
    cross_functional: Math.max(0, classes.size - 1),
    data_volume: dbRowsByTrace,
  };
  return features;
}

export function scoreFeatures(features) {
  let total = 0;
  const contributions = [];
  for (const f of FEATURES) {
    const value = Number(features[f.name] ?? 0);
    const contribution = Math.round(clamp(value / f.max, 0, 1) * f.weight * 10) / 10;
    total += contribution;
    contributions.push({
      name: f.name,
      describe: f.describe,
      value,
      weight: f.weight,
      contribution,
    });
  }
  const score = Math.round(clamp(total, 0, 100));
  const level = score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'ELEVATED' : 'LOW';
  return { score, level, contributions };
}

export async function updateRisk(actorId, username, windowSeconds = 600) {
  if (actorId == null) return null;
  const windowEvents = await recentWindow(actorId, windowSeconds);
  if (!windowEvents.length) return null;
  const features = extractFeatures(windowEvents);
  const { score, level, contributions } = scoreFeatures(features);
  await saveRisk(actorId, username ?? windowEvents[0].username, score, level, { features, contributions });
  return { score, level, contributions, features };
}
