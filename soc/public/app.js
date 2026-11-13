/* Loopback SOC — operator console logic */
(() => {
  const $ = (id) => document.getElementById(id);
  const TOKEN_KEY = 'loopback_soc_token';

  const state = {
    token: sessionStorage.getItem(TOKEN_KEY) || null,
    alerts: [],
    events: [],
    users: [],
    actions: [],
    sevFilter: '',
    typeFilter: '',
    srcFilter: '',
    currentUser: null,
    pollTimer: null,
    apiKey: null,
  };

  async function api(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    const res = await fetch(path, { ...opts, headers });
    let data = {};
    try { data = await res.json(); } catch { /* empty */ }
    if (res.status === 401 && state.token) { logout(); }
    return { ok: res.ok, status: res.status, data };
  }

  function esc(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function timeOf(ts, full = false) {
    try {
      const d = new Date(ts).toISOString();
      return full ? d.replace('T', ' ').slice(0, 19) : d.slice(11, 19);
    } catch { return '—'; }
  }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.add('hidden'), 3200);
  }

  /* ---------- gate ---------- */
  $('gateForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('gateError').classList.add('hidden');
    const btn = $('gateBtn');
    btn.disabled = true;
    btn.textContent = 'Authenticating…';
    try {
      const { ok, data } = await api('/api/login', {
        method: 'POST',
        body: JSON.stringify({ username: $('gateUser').value.trim(), password: $('gatePass').value.trim() }),
      });
      if (!ok || !data.success) {
        const el = $('gateError');
        el.textContent = data.error || 'Authentication failed';
        el.classList.remove('hidden');
        return;
      }
      // Show the login flow the SOC processed for this operator
      const flow = $('gateFlow');
      flow.classList.remove('hidden');
      flow.innerHTML = (data.loginFlow || []).map((s, i) => `<div>✓ step ${i + 1}: ${esc(s)}</div>`).join('');
      await new Promise((r) => setTimeout(r, 700));
      state.token = data.token;
      sessionStorage.setItem(TOKEN_KEY, data.token);
      enterConsole();
    } catch (err) {
      const el = $('gateError');
      el.textContent = 'Network error — is the SOC server running?';
      el.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Access Console';
    }
  });

  function logout() {
    state.token = null;
    sessionStorage.removeItem(TOKEN_KEY);
    if (state.pollTimer) clearInterval(state.pollTimer);
    $('console').classList.add('hidden');
    $('gate').classList.remove('hidden');
  }

  $('logoutBtn').addEventListener('click', logout);

  function enterConsole() {
    $('gate').classList.add('hidden');
    $('console').classList.remove('hidden');
    refreshAll();
    loadSettings();
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(refreshAll, 2500);
  }

  /* ---------- tabs ---------- */
  document.querySelectorAll('.nav-btn').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.nav-btn').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
      $(`panel-${tab.dataset.tab}`).classList.add('active');
      const which = tab.dataset.tab;
      if (which === 'actions') loadActions();
      if (which === 'users') loadUsers();
    });
  });

  /* ---------- refresh core ---------- */
  async function refreshAll() {
    const [statsRes, eventsRes, alertsRes, usersRes] = await Promise.all([
      api('/api/stats'),
      api('/api/events?limit=250'),
      api('/api/alerts'),
      api('/api/users'),
    ]);
    if (usersRes.ok) { state.users = usersRes.data.users || []; renderUsersTable(); }
    if (alertsRes.ok) { state.alerts = alertsRes.data.alerts || []; renderAlerts(); }
    if (statsRes.ok) renderOverview(statsRes.data);
    if (eventsRes.ok) renderTraffic(eventsRes.data.events || []);
    if (statsRes.ok) loadRecentActions();
  }

  async function loadRecentActions() {
    const res = await api('/api/actions?limit=12');
    if (res.ok) renderRecentActions(res.data.actions || []);
  }

  /* ---------- overview ---------- */
  function renderOverview({ stats: s, severityBreakdown: sev }) {
    if (!s) return;
    $('stApi').textContent = s.api_events ?? 0;
    $('stDb').textContent = s.db_events ?? 0;
    $('stAlerts').textContent = s.alerts ?? 0;
    $('stCritical').textContent = s.critical ?? 0;
    $('stActors').textContent = s.actors ?? 0;
    $('stBlocked').textContent = s.blocked_users ?? 0;
    $('stAuto').textContent = s.autonomous_actions ?? 0;
    $('stRisk').textContent = s.avg_risk ?? 0;
    const pill = $('alertCount');
    pill.textContent = s.alerts ?? 0;
    pill.classList.toggle('hidden', !(s.alerts > 0));

    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO'];
    const maxN = Math.max(1, ...(sev || []).map((x) => x.n));
    $('sevBars').innerHTML = order.map((o) => {
      const n = sev?.find((x) => x.severity === o)?.n ?? 0;
      return `<div class="sev-bar sev-${o}"><span class="slabel">${o}</span><span class="sbar"><span class="sfill" style="width:${Math.round((n / maxN) * 100)}%"></span></span><span class="snum">${n}</span></div>`;
    }).join('');

    const top = [...state.users].sort((a, b) => (b.risk || 0) - (a.risk || 0)).slice(0, 6);
    $('riskBoard').innerHTML = top.length
      ? top.map((u) => `<div class="risk-row"><span class="rname">${esc(u.username || `#${u.actor_id}`)}</span><span class="rbar"><span class="rfill risk-${u.risk_level}" style="width:${u.risk || 0}%"></span></span><span class="rscore">${u.risk || 0}</span></div>`).join('')
      : '<div class="mini-row"><span class="x muted">No tracked users yet</span></div>';

    const ra = state.alerts.slice(0, 6);
    $('recentAlerts').innerHTML = ra.length
      ? ra.map((a) => `<div class="mini-row"><span class="t">${timeOf(a.ts)}</span><span class="s sev-${a.severity}" style="color:inherit">${a.severity}</span><span class="x">${esc(a.title)}</span></div>`).join('')
      : '<div class="mini-row"><span class="x muted">No alerts yet</span></div>';
  }

  async function renderRecentActions(actions) {
    $('recentActions').innerHTML = actions.length
      ? actions.slice(0, 6).map((a) => `<div class="mini-row"><span class="t">${timeOf(a.ts)}</span><span class="s src-${String(a.source).toUpperCase()}">${esc(a.source)}</span><span class="x">${esc(a.kind)} → ${esc(String(a.target_value).slice(0, 20))}</span></div>`).join('')
      : '<div class="mini-row"><span class="x muted">No actions yet</span></div>';
  }

  /* ---------- live traffic ---------- */
  function trafficFilters(events) {
    const fApi = $('fApi').value;
    const fUser = $('fUser').value.trim().toLowerCase();
    const fEp = $('fEp').value.trim().toLowerCase();
    return events.filter((e) =>
      (!fApi || e.api === fApi) &&
      (!fUser || String(e.username || '').toLowerCase().includes(fUser)) &&
      (!fEp || String(e.endpoint).toLowerCase().includes(fEp))
    );
  }

  function renderTraffic(events) {
    state.events = events;
    const stream = $('trafficStream');
    const filtered = trafficFilters(events);
    if (!filtered.length) {
      stream.innerHTML = '<div class="ev-row"><span class="muted">[NO TRAFFIC — OPEN THE BANKING PORTAL ON :5000 AND MAKE REQUESTS]</span></div>';
      return;
    }
    const frag = document.createDocumentFragment();
    for (const e of filtered) {
      const row = document.createElement('div');
      row.className = 'ev-row';
      const err = e.status_code >= 400;
      const apiChip = String(e.api || 'rest').toUpperCase();
      const op = e.operation ? ` • ${esc(e.operation)}` : '';
      const dev = e.user_agent ? String(e.user_agent).replace(/\([^)]*\)/g, '').trim().split(' ').slice(0, 2).join(' ') : '—';
      row.innerHTML = `
        <span class="ts">${timeOf(e.ts)}</span>
        <span class="api-chip api-${apiChip === 'GRAPHQL' ? 'GRAPHQL' : 'REST'}">${apiChip}</span>
        <span class="user">${esc(e.username || 'ANON')}</span>
        <span class="uid">#${e.actor_id ?? '–'}</span>
        <span class="ipdev">${esc(e.ip || '')} · ${esc(dev)}</span>
        <span class="ep">${esc(e.method)} ${esc(e.endpoint)}${op}</span>
        <span class="${err ? 'status-err' : 'status-ok'}">${e.status_code}</span>
        <span class="trace-tag">⌥ ${esc(String(e.trace_id).slice(0, 8))}</span>`;
      frag.appendChild(row);

      for (const q of e.db_queries || []) {
        const sub = document.createElement('div');
        sub.className = 'db-sub';
        sub.innerHTML = `<span class="tag">SQL</span>${esc(q.template || q.query)}${q.rowCount != null ? ` <span class="trace-tag">(${q.rowCount} rows)</span>` : ''}`;
        frag.appendChild(sub);
      }
    }
    stream.innerHTML = '';
    stream.appendChild(frag);
  }

  ['fApi', 'fUser', 'fEp'].forEach((id) => $(id).addEventListener('input', () => renderTraffic(state.events)));

  /* ---------- users ---------- */
  async function loadUsers() {
    const res = await api('/api/users');
    if (res.ok) { state.users = res.data.users || []; renderUsersTable(); }
  }

  function renderUsersTable() {
    const body = $('usersBody');
    if (!state.users.length) {
      body.innerHTML = '<tr><td colspan="11" class="muted mono" style="padding:16px">[NO TRACKED USERS YET — MAKE REQUESTS ON THE BANK]</td></tr>';
      return;
    }
    body.innerHTML = '';
    for (const u of state.users) {
      const tr = document.createElement('tr');
      const ips = (u.ips || []).slice(0, 2).join(', ') || '—';
      const dev = (u.devices || [])[0];
      const device = dev ? `${String(dev.ua || '').replace(/\([^)]*\)/g, '').trim().split(' ').slice(0, 2).join(' ')}` : '—';
      tr.innerHTML = `
        <td class="mono">${u.actor_id}</td>
        <td><strong>${esc(u.username || '—')}</strong></td>
        <td class="mono">${esc(ips)}</td>
        <td>${u.api_events}</td>
        <td>${u.distinct_endpoints}</td>
        <td>${u.errors || 0}</td>
        <td>${u.alerts}</td>
        <td><span class="risk-pill"><span class="risk-dot risk-${u.risk_level}" style="background:var(--${u.risk_level === 'CRITICAL' ? 'rose' : u.risk_level === 'HIGH' ? 'amber' : u.risk_level === 'ELEVATED' ? 'cyan' : 'emerald'})"></span>${u.risk || 0} ${esc(u.risk_level || '')}</span></td>
        <td><span class="status-chip st-${u.blocked ? 'BLOCKED' : 'ACTIVE'}">${u.blocked ? 'BLOCKED' : 'ACTIVE'}</span></td>
        <td class="mono">${timeOf(u.last_seen, true)}</td>
        <td><button class="btn ghost small" data-uid="${u.actor_id}" type="button">Investigate</button></td>`;
      tr.querySelector('[data-uid]').addEventListener('click', () => openUser(u.actor_id));
      body.appendChild(tr);
    }
  }

  async function openUser(actorId) {
    state.currentUser = actorId;
    const res = await api(`/api/users/${actorId}`);
    if (!res.ok) return;
    const d = res.data;
    $('userDetail').classList.remove('hidden');
    const u = state.users.find((x) => x.actor_id === actorId) || {};
    $('udTitle').textContent = `${u.username || 'User'} (ID ${actorId}) — investigation view`;

    const devices = (u.devices || []).map((x) => `${x.ip} — ${String(x.ua || '').slice(0, 60)}`).join('<br/>') || '—';
    $('udProfile').innerHTML = `
      <h3>Identity &amp; devices</h3>
      <div class="profile-line"><span class="plabel">Client ID</span><span class="pval">${actorId}</span></div>
      <div class="profile-line"><span class="plabel">Username</span><span class="pval">${esc(u.username || '—')}</span></div>
      <div class="profile-line"><span class="plabel">IPs seen</span><span class="pval">${esc((u.ips || []).join(', ') || '—')}</span></div>
      <div class="profile-line"><span class="plabel">Devices</span><span class="pval">${devices}</span></div>
      <div class="profile-line"><span class="plabel">First seen</span><span class="pval">${timeOf(u.first_seen, true) || '—'}</span></div>
      <div class="profile-line"><span class="plabel">Last seen</span><span class="pval">${timeOf(u.last_seen, true) || '—'}</span></div>
      <div class="profile-line"><span class="plabel">Requests / SQL endpoints</span><span class="pval">${u.api_events} / ${u.distinct_endpoints} classes</span></div>
      <div class="profile-line"><span class="plabel">Errors</span><span class="pval">${u.errors || 0}</span></div>
      <div class="profile-line"><span class="plabel">Alerts</span><span class="pval">${u.alerts}</span></div>`;

    const r = d.risk;
    $('udRisk').innerHTML = r
      ? `<div class="profile-line"><span class="plabel">Risk score</span><span class="pval"><strong>${r.score}</strong> / 100 (${esc(r.level)})</span></div>` +
        (r.features?.contributions || []).map((f) => `
          <div class="risk-feature">
            <div class="rf-top"><span class="rf-name">${esc(f.name)}</span><span class="rf-val">${f.value} → +${f.contribution} / ${f.weight}</span></div>
            <div class="rf-bar"><div class="rf-fill" style="width:${Math.round((f.contribution / f.weight) * 100)}%"></div></div>
            <div class="muted" style="font-size:10px">${esc(f.describe)}</div>
          </div>`).join('')
      : '<span class="muted">No risk data yet.</span>';

    $('udActions').innerHTML = (d.actions || []).length
      ? d.actions.slice(0, 8).map((a) => `<div class="mini-row"><span class="t">${timeOf(a.ts, true)}</span><span class="s src-${String(a.source).toUpperCase()}">${esc(a.source)}</span><span class="x">${esc(a.kind)} — ${esc(String(a.reason || '').slice(0, 90))}</span></div>`).join('')
      : '<div class="mini-row"><span class="x muted">No actions taken on this user yet.</span></div>';

    const tl = $('udActivity');
    tl.innerHTML = '';
    for (const e of (d.activity || []).slice(0, 60)) {
      const row = document.createElement('div');
      row.className = 'tl-row';
      const err = e.status_code >= 400;
      row.innerHTML = `
        <span class="ts">${timeOf(e.ts, true)}</span>
        <span class="ep">${esc(e.method)} ${esc(e.endpoint)} → <span class="${err ? 'status-err' : 'status-ok'}">${e.status_code}</span> · ${esc(e.ip || '')} · ${esc(String(e.api || '').toUpperCase())}</span>
        <span class="trace">${esc(String(e.trace_id).slice(0, 8))}</span>`;
      tl.appendChild(row);
      for (const q of e.db_queries || []) {
        const sql = document.createElement('div');
        sql.className = 'tl-sql';
        sql.textContent = `↳ SQL ${q.template || q.query}`;
        tl.appendChild(sql);
      }
    }
    if (!(d.activity || []).length) tl.innerHTML = '<span class="muted mono">No activity recorded.</span>';
    $('userDetail').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  $('udClose').addEventListener('click', () => $('userDetail').classList.add('hidden'));

  $('udBlock').addEventListener('click', async () => {
    if (!state.currentUser) return;
    await applyResponse('block_user', state.currentUser, `Blocked from investigation view (user ${state.currentUser})`);
    loadUsers();
    openUser(state.currentUser);
  });
  $('udRevoke').addEventListener('click', async () => {
    if (!state.currentUser) return;
    const res = await api(`/api/users/${state.currentUser}`);
    const token = res.ok ? res.data.activity?.[0]?.session_token || res.data.activity?.find((a) => a.session_token)?.session_token : null;
    if (!token) { toast('No live session token found in recent activity.'); return; }
    await applyResponse('revoke_session', token, `Session revoked from investigation view (user ${state.currentUser})`);
    loadUsers();
  });
  $('udUnblock').addEventListener('click', async () => {
    if (!state.currentUser) return;
    await applyResponse('unblock_user', state.currentUser, `Unblocked from investigation view (user ${state.currentUser})`);
    loadUsers();
    openUser(state.currentUser);
  });

  /* ---------- alerts ---------- */
  document.querySelectorAll('#alertFilters .fchip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const parent = chip.parentElement;
      const sevChips = parent.querySelectorAll('[data-sev]');
      const typeChips = parent.querySelectorAll('[data-type]');
      if (chip.dataset.sev != null && chip.dataset.sev !== undefined && chip.hasAttribute('data-sev')) {
        sevChips.forEach((c) => c.classList.remove('active'));
        chip.classList.add('active');
        state.sevFilter = chip.dataset.sev || '';
      } else {
        typeChips.forEach((c) => c.classList.remove('active'));
        chip.classList.add('active');
        state.typeFilter = chip.dataset.type || '';
      }
      renderAlerts();
    });
  });

  function filteredAlerts() {
    return state.alerts.filter((a) =>
      (!state.sevFilter || a.severity === state.sevFilter) &&
      (!state.typeFilter || a.alert_type === state.typeFilter)
    );
  }

  // Severity as a percentage 0–100, coloured on a continuous green → red scale
  function sevPctOf(a) {
    if (a.severity_pct != null) return a.severity_pct;
    const base = { INFO: 10, MEDIUM: 35, HIGH: 65, CRITICAL: 88 }[a.severity] ?? 40;
    return Math.min(99, base + Math.min(25, ((a.attempts || 1) - 1) * 9) + (a.is_cross_functional ? 6 : 0));
  }
  function sevColor(pct) {
    const hue = Math.round(120 - (pct / 100) * 120); // 120 = green, 60 = orange, 0 = red
    return `hsl(${hue}, 76%, 52%)`;
  }

  // Alerts the operator has expanded — preserved across auto-refresh rebuilds
  const expandedAlerts = new Set();
  let lastAlertSig = '';

  function renderAlerts() {
    const alerts = filteredAlerts();
    $('alertsEmpty').classList.toggle('hidden', alerts.length > 0);
    // Rebuild only when something actually changed — rebuilding the DOM every
    // 2.5s collapsed the operator's expansion and could eat their clicks.
    const sig = alerts.map((a) => a.id + ':' + JSON.stringify(a.response || {})).join('|');
    if (sig === lastAlertSig && $('alertsList').children.length) return;
    lastAlertSig = sig;
    const list = $('alertsList');
    list.innerHTML = '';
    for (const a of alerts) {
      const card = document.createElement('div');
      card.className = 'alert-card';
      const pct = sevPctOf(a);
      const color = sevColor(pct);
      const eps = (a.affected_endpoints || []).length;
      const resp = a.response || {};
      const respBits = [];
      if (resp.blocked) respBits.push('USER BLOCKED');
      if (resp.sessionRevoked) respBits.push('SESSION REVOKED');
      if (resp.dismissed) respBits.push('DISMISSED');
      const typeShort = a.alert_type === 'POSSIBLE_IDOR_ATTACK' ? 'IDOR'
        : a.alert_type === 'POSSIBLE_BUSINESS_LOGIC_ATTACK' ? 'BUSINESS LOGIC'
        : a.alert_type === 'SUSPICIOUS_SESSION_ANOMALY' ? 'SESSION HIJACK'
        : a.alert_type === 'REFLECTED_XSS_ATTACK' ? 'XSS'
        : a.alert_type === 'SQL_INJECTION_ATTACK' ? 'SQLi'
        : 'ENUMERATION';
      card.innerHTML = `
        <div class="alert-row">
          <span class="sev-ring" title="${pct}% severity">
            <svg viewBox="0 0 56 56">
              <circle class="ring-bg" cx="28" cy="28" r="24"/>
              <circle class="ring-fg" cx="28" cy="28" r="24" stroke="${color}" stroke-dasharray="${(2 * Math.PI * 24).toFixed(1)}" stroke-dashoffset="${(2 * Math.PI * 24 * (1 - pct / 100)).toFixed(1)}"/>
              <text x="28" y="33" text-anchor="middle" fill="${color}">${pct}<tspan font-size="8">%</tspan></text>
            </svg>
          </span>
          <div class="alert-row-main">
            <div class="alert-row-title">${esc(a.title)}</div>
            <div class="alert-row-sub">
              <span class="type-chip">${typeShort}</span>
              <span class="sev-word" style="color:${color}">${esc(a.severity)}</span>
              <span class="mono">• ${esc(a.username || '—')}</span>
              <span class="mono">• ${timeOf(a.ts)}</span>
              ${a.is_cross_functional ? '<span class="cross-flag">cross-functional</span>' : ''}
              ${respBits.length ? `<span class="resp-flag">${esc(respBits.join(' · '))}</span>` : ''}
            </div>
          </div>
          <button class="alert-expand" type="button" aria-label="Expand alert">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
          </button>
        </div>
        <div class="alert-body hidden">
          <div class="alert-summary">${esc(a.summary)}</div>
          <div class="alert-strip">
            <span>Actor: <strong>${esc(a.username || '—')}</strong></span>
            <span>Endpoints: <strong>${eps}</strong></span>
            <span>Trace: <strong>${esc(String(a.evidence?.traceId || '').slice(0, 8))}</strong></span>
            <span>Severity: <strong style="color:${color}">${pct}%</strong></span>
          </div>
          <div class="alert-actions">
            <button class="btn brain" data-act="path" type="button">Attack Path</button>
            <button class="btn ghost" data-act="evidence" type="button">Evidence</button>
            <button class="btn danger" data-act="block" type="button">Block User</button>
            <button class="btn warn" data-act="revoke" type="button">Revoke Session</button>
            <button class="btn ghost" data-act="dismiss" type="button">Dismiss</button>
          </div>
        </div>`;
      const expandBtn = card.querySelector('.alert-expand');
      const body = card.querySelector('.alert-body');
      if (expandedAlerts.has(a.id)) {
        body.classList.remove('hidden');
        expandBtn.classList.add('open');
      }
      expandBtn.addEventListener('click', () => {
        body.classList.toggle('hidden');
        expandBtn.classList.toggle('open');
        if (body.classList.contains('hidden')) expandedAlerts.delete(a.id);
        else expandedAlerts.add(a.id);
      });
      card.querySelector('[data-act="path"]').addEventListener('click', () => openPath(a));
      card.querySelector('[data-act="evidence"]').addEventListener('click', () => openEvidence(a));
      card.querySelector('[data-act="block"]').addEventListener('click', () =>
        applyResponse('block_user', a.actor_id ?? a.evidence?.actorId, `Blocked for ${a.alert_type} (${a.severity}) — ${a.title}`, a.id));
      card.querySelector('[data-act="revoke"]').addEventListener('click', () => {
        const token = a.evidence?.sessionToken || a.evidence?.session_token;
        if (!token) { toast('No session token in this alert\'s evidence.'); return; }
        applyResponse('revoke_session', token, `Session revoked for ${a.alert_type} — ${a.title}`, a.id);
      });
      card.querySelector('[data-act="dismiss"]').addEventListener('click', () =>
        applyResponse('dismiss_alert', a.id, `Dismissed ${a.alert_type}`, a.id));
      list.appendChild(card);
    }
  }

  async function applyResponse(kind, value, reason, alertId) {
    const res = await api('/api/actions', {
      method: 'POST',
      body: JSON.stringify({ kind, value: String(value), reason, alertId }),
    });
    if (res.ok && res.data.success) {
      toast(`${kind} applied${res.data.push && res.data.push.ok === false ? ' (push to target failed — target offline?)' : ''}.`);
      const alertsRes = await api('/api/alerts');
      if (alertsRes.ok) { state.alerts = alertsRes.data.alerts || []; renderAlerts(); }
      loadRecentActions();
    } else {
      toast(res.data?.error || 'Action failed.');
    }
  }

  /* ---------- attack path (interactive layered graph with icons) ---------- */
  const LAYER_COLORS = {
    device: '#fb7185', session: '#c084fc', endpoint: '#2dd4bf',
    query: '#34d399', database: '#fbbf24', data: '#fbbf24',
    reflection: '#a5b4fc', sink: '#fb923c', impact: '#a5b4fc',
  };
  const LAYER_TITLES = {
    device: 'Client device', session: 'Session', endpoint: 'API endpoint',
    query: 'Malformed / correlated SQL', database: 'Database', data: 'Database tables',
    reflection: 'Reflected input', sink: 'Client DOM sink', impact: 'Impact',
  };
  let pathZoom = 1;

  // Small stroke icons drawn per layer, centred at (cx, cy)
  function layerIcon(layer, cx, cy, color) {
    const s = `stroke="${color}" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"`;
    switch (layer) {
      case 'device': // laptop
        return `<g ${s}><rect x="${cx - 9}" y="${cy - 7}" width="18" height="11" rx="1.5"/><path d="M${cx - 12} ${cy + 7} h24"/></g>`;
      case 'session': // key
        return `<g ${s}><circle cx="${cx - 4}" cy="${cy}" r="3.6"/><path d="M${cx - 0.4} ${cy} h10 M${cx + 6} ${cy} v4 M${cx + 9.6} ${cy} v3"/></g>`;
      case 'endpoint': // globe
        return `<g ${s}><circle cx="${cx}" cy="${cy}" r="8"/><path d="M${cx - 8} ${cy} h16 M${cx} ${cy - 8} c3 2.5 3 13.5 0 16 M${cx} ${cy - 8} c-3 2.5 -3 13.5 0 16"/></g>`;
      case 'query': // database
        return `<g ${s}><ellipse cx="${cx}" cy="${cy - 5}" rx="8" ry="3.2"/><path d="M${cx - 8} ${cy - 5} v10 c0 1.8 3.6 3.2 8 3.2 s8 -1.4 8 -3.2 v-10"/><path d="M${cx - 8} ${cy} c0 1.8 3.6 3.2 8 3.2 s8 -1.4 8 -3.2"/></g>`;
      case 'database': // database with error mark
        return `<g ${s}><ellipse cx="${cx}" cy="${cy - 5}" rx="8" ry="3.2"/><path d="M${cx - 8} ${cy - 5} v10 c0 1.8 3.6 3.2 8 3.2 s8 -1.4 8 -3.2 v-10"/><path d="M${cx + 5} ${cy + 3} l6 6 M${cx + 11} ${cy + 3} l-6 6"/></g>`;
      case 'data': // table
        return `<g ${s}><rect x="${cx - 8}" y="${cy - 7}" width="16" height="14" rx="1.5"/><path d="M${cx - 8} ${cy - 2.5} h16 M${cx - 2.5} ${cy - 7} v14 M${cx + 3} ${cy - 7} v14"/></g>`;
      case 'reflection': // code brackets
        return `<g ${s}><polyline points="${cx - 7},${cy - 6} ${cx - 11},${cy} ${cx - 7},${cy + 6}"/><polyline points="${cx + 7},${cy - 6} ${cx + 11},${cy} ${cx + 7},${cy + 6}"/><path d="M${cx - 1} ${cy + 5} l2 -10"/></g>`;
      case 'sink': // bug
        return `<g ${s}><rect x="${cx - 5}" y="${cy - 4}" width="10" height="9" rx="4.5"/><path d="M${cx - 5} ${cy} h-4 M${cx + 5} ${cy} h4 M${cx - 4} ${cy - 5} l-3 -3 M${cx + 4} ${cy - 5} l3 -3 M${cx - 4} ${cy + 6} l-3 3 M${cx + 4} ${cy + 6} l3 3"/></g>`;
      case 'impact': // alert triangle
        return `<g ${s}><path d="M${cx} ${cy - 8} l8 14 h-16 z"/><path d="M${cx} ${cy - 1} v3.5"/><circle cx="${cx}" cy="${cy + 4.2}" r="0.5"/></g>`;
      default:
        return `<circle cx="${cx}" cy="${cy}" r="6" ${s}/>`;
    }
  }

  let pathPositions = [];

  function renderPathGraph(nodes, edges) {
    const W = 920, nodeW = 128, colW = 140, y0 = 76, nodeH = 96;
    const cols = [...new Set(nodes.map((n) => n.layer || 'api'))];
    const byLayer = new Map(cols.map((c) => [c, []]));
    nodes.forEach((n) => byLayer.get(n.layer || 'api').push(n));
    pathPositions = [];
    let maxRows = 1;
    cols.forEach((c, ci) => {
      const arr = byLayer.get(c);
      maxRows = Math.max(maxRows, arr.length);
      arr.forEach((n, ri) => {
        positions_push(n, 40 + ci * (nodeW + colW), y0 + ri * (nodeH + 26), ci);
      });
    });
    function positions_push(n, x, y, col) { pathPositions.push({ node: n, x, y, col }); }

    const H = y0 + maxRows * (nodeH + 26) + 40;
    const header = cols.map((c, ci) => {
      const x = 40 + ci * (nodeW + colW);
      return `<text x="${x + nodeW / 2}" y="34" text-anchor="middle" fill="#93a89e" font-size="12" font-family="monospace" letter-spacing="2">${esc(String(c).toUpperCase())}</text>`;
    }).join('');

    // Animated connection lines between entity centers — no boxes, just icons
    const edgeLines = edges.map((e) => {
      const f = pathPositions[e.from];
      const t = pathPositions[e.to];
      if (!f || !t) return '';
      const x1 = f.x + nodeW / 2, y1 = f.y;
      const x2 = t.x + nodeW / 2, y2 = t.y;
      const mid = (x1 + x2) / 2;
      return `<path d="M${x1},${y1 - 34} C${mid},${y1 - 34} ${mid},${y2 + 34} ${x2},${y2 + 34}" stroke="#2dd4bf55" fill="none" stroke-width="2" class="edge-anim"/>
        <text x="${mid}" y="${(y1 + y2) / 2}" text-anchor="middle" fill="#93a89e" font-size="10" font-family="monospace">${esc(e.label || '')}</text>`;
    }).join('');

    // Boxless nodes: colored icon disc + entity label underneath
    const nodeMarks = pathPositions.map((p, i) => {
      const color = LAYER_COLORS[p.node.layer] || '#2dd4bf';
      const label = String(p.node.label || '').slice(0, 26);
      return `
        <g class="pnode" data-idx="${i}">
          <circle cx="${p.x + nodeW / 2}" cy="${p.y}" r="30" fill="#111b17" stroke="${color}" stroke-width="2"/>
          ${layerIcon(p.node.layer, p.x + nodeW / 2, p.y, color)}
          <text x="${p.x + nodeW / 2}" y="${p.y + 48}" text-anchor="middle" fill="#ecf3ee" font-size="10" font-weight="bold" font-family="monospace">${esc(label)}</text>
          <title>${esc(String(p.node.details || ''))}</title>
        </g>`;
    }).join('');

    $('pathGraph').innerHTML = `<svg width="100%" viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">${header}${edgeLines}${nodeMarks}</svg>`;

    // Interactivity: click (or hover) a node to open its full details below
    const showDetail = (el) => {
      $('pathGraph').querySelectorAll('.pnode').forEach((n) => n.classList.remove('selected'));
      el.classList.add('selected');
      const p = pathPositions[Number(el.dataset.idx)];
      const color = LAYER_COLORS[p.node.layer] || '#2dd4bf';
      const box = $('pathNodeDetail');
      box.style.borderLeftColor = color;
      box.innerHTML = `
        <h4 style="color:${color}">${esc(LAYER_TITLES[p.node.layer] || p.node.layer)} — ${esc(p.node.label)}</h4>
        <p>${esc(p.node.details)}</p>
        ${(p.node.statements || []).map((s) => `<p class="mono" style="font-size:11px;color:#99f6e4">↳ ${esc(s)}</p>`).join('')}`;
      box.classList.remove('hidden');
    };
    $('pathGraph').querySelectorAll('.pnode').forEach((el) => {
      el.addEventListener('click', () => showDetail(el));
      el.addEventListener('mouseenter', () => showDetail(el));
    });
  }

  function wrapSvgText(text, maxW, size) {
    const charsPerLine = Math.floor(maxW / (size * 0.5));
    const words = String(text).split(' ');
    const lines = [];
    let cur = '';
    for (const w of words) {
      if ((cur + ' ' + w).length > charsPerLine) { lines.push(cur); cur = w; } else cur = cur ? cur + ' ' + w : w;
    }
    if (cur) lines.push(cur);
    return lines.slice(0, 3);
  }

  function openPath(a) {
    $('pathTitle').textContent = a.title;
    $('pathSub').textContent = `${a.alert_type} • ${a.severity} • trace ${String(a.evidence?.traceId || '').slice(0, 8)}`;
    const ap = a.attack_path || {};
    $('pathNodeDetail').classList.add('hidden');
    pathZoom = 1;
    renderPathGraph(ap.nodes || [], ap.edges || []);
    const stepsEl = $('pathSteps');
    stepsEl.innerHTML = '';
    for (const s of ap.steps || []) {
      const row = document.createElement('div');
      row.className = 'step-row';
      row.innerHTML = `
        <div class="step-num">${s.step}</div>
        <div class="step-body">
          <div class="step-title">${esc(s.title)}</div>
          <div class="step-desc">${esc(s.description)}</div>
        </div>
        <span class="step-status st-${esc(s.status)}">${esc(s.status)}</span>`;
      stepsEl.appendChild(row);
    }
    $('pathModal').classList.remove('hidden');
  }

  // Adjustable zoom on the attack-path graph
  function applyZoom() {
    const svg = document.querySelector('#pathGraph svg');
    if (svg) {
      svg.style.transform = `scale(${pathZoom})`;
      svg.style.transformOrigin = 'top left';
    }
    $('zoomLevel').textContent = `${Math.round(pathZoom * 100)}%`;
  }
  $('zoomIn').addEventListener('click', () => { pathZoom = Math.min(2.5, pathZoom + 0.25); applyZoom(); });
  $('zoomOut').addEventListener('click', () => { pathZoom = Math.max(0.5, pathZoom - 0.25); applyZoom(); });
  $('zoomReset').addEventListener('click', () => { pathZoom = 1; applyZoom(); });
  $('pathClose').addEventListener('click', () => $('pathModal').classList.add('hidden'));
  $('pathModal').addEventListener('click', (e) => { if (e.target === $('pathModal')) $('pathModal').classList.add('hidden'); });

  function openEvidence(a) {
    $('evTitle').textContent = a.title;
    $('evJson').textContent = JSON.stringify({
      alert: { id: a.id, type: a.alert_type, severity: a.severity, attempts: a.attempts, crossFunctional: a.is_cross_functional, response: a.response },
      affectedEndpoints: a.affected_endpoints,
      evidence: a.evidence,
      attackPathSteps: a.attack_path?.steps,
    }, null, 2);
    $('evModal').classList.remove('hidden');
  }
  $('evClose').addEventListener('click', () => $('evModal').classList.add('hidden'));
  $('evModal').addEventListener('click', (e) => { if (e.target === $('evModal')) $('evModal').classList.add('hidden'); });

  /* ---------- actions log ---------- */
  document.querySelectorAll('#panel-actions .fchip').forEach((chip) => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('#panel-actions .fchip').forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      state.srcFilter = chip.dataset.src || '';
      loadActions();
    });
  });

  async function loadActions() {
    const res = await api('/api/actions?limit=200');
    if (!res.ok) return;
    const actions = (res.data.actions || []).filter((a) => !state.srcFilter || a.source === state.srcFilter);
    const body = $('actionsBody');
    body.innerHTML = '';
    if (!actions.length) {
      body.innerHTML = '<tr><td colspan="6" class="muted mono" style="padding:16px">[NO RESPONSE ACTIONS YET]</td></tr>';
      return;
    }
    for (const a of actions) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mono">${timeOf(a.ts, true)}</td>
        <td><strong>${esc(a.kind)}</strong></td>
        <td class="mono">${esc(String(a.target_value).slice(0, 26))}</td>
        <td><span class="s src-${String(a.source).toUpperCase()}">${esc(a.source)}</span></td>
        <td class="mono">${esc(a.operator || '—')}</td>
        <td class="muted" style="max-width:340px">${esc(String(a.reason || '').slice(0, 140))}</td>`;
      body.appendChild(tr);
    }
  }

  /* ---------- settings ---------- */
  async function loadSettings() {
    const res = await api('/api/settings');
    if (!res.ok) return;
    const s = res.data.settings || {};
    $('setAutoBlock').checked = !!s.auto_block_enabled;
    $('setAutoBlockSev').value = s.auto_block_severity || 'CRITICAL';
    $('setAutoRevoke').checked = !!s.auto_revoke_enabled;
    $('setAutoRevokeSev').value = s.auto_revoke_severity || 'CRITICAL';
    $('setRiskThreshold').value = Number(s.risk_threshold ?? 75);
    $('setRiskVal').textContent = Number(s.risk_threshold ?? 75);
    state.apiKey = res.data.apiKey;
    $('apiKeyVal').textContent = state.apiKey || '—';
    $('opName').textContent = `operator: ${res.data.operator || 'admin'}`;
  }

  $('setRiskThreshold').addEventListener('input', () => { $('setRiskVal').textContent = $('setRiskThreshold').value; });

  $('setSave').addEventListener('click', async () => {
    const res = await api('/api/settings', {
      method: 'PUT',
      body: JSON.stringify({
        auto_block_enabled: $('setAutoBlock').checked,
        auto_block_severity: $('setAutoBlockSev').value,
        auto_revoke_enabled: $('setAutoRevoke').checked,
        auto_revoke_severity: $('setAutoRevokeSev').value,
        risk_threshold: Number($('setRiskThreshold').value),
      }),
    });
    if (res.ok) toast('Autonomous response policy saved.');
  });

  $('apiKeyCopy').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('apiKeyVal').textContent); toast('API key copied.'); }
    catch { toast('Copy failed — select manually.'); }
  });

  $('apiKeyRotate').addEventListener('click', async () => {
    const res = await api('/api/settings/apikey/rotate', { method: 'POST' });
    if (res.ok) { state.apiKey = res.data.apiKey; $('apiKeyVal').textContent = state.apiKey; toast('API key rotated.'); }
  });

  $('clearBtn').addEventListener('click', async () => {
    if (!confirm('Clear all SOC events, alerts and actions?')) return;
    await api('/api/clear', { method: 'POST' });
    refreshAll();
  });

  /* ---------- boot ---------- */
  (async () => {
    if (!state.token) return;
    const { ok } = await api('/api/stats');
    if (ok) enterConsole();
    else logout();
  })();
})();
