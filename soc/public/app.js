/* Loopback SOC — operator console logic */
(() => {
  const $ = (id) => document.getElementById(id);
  const TOKEN_KEY = 'loopback_soc_token';

  const state = {
    token: sessionStorage.getItem(TOKEN_KEY) || null,
    alerts: [],
    events: [],
    pollTimer: null,
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

  function timeOf(ts) {
    try { return new Date(ts).toISOString().replace('T', ' ').substring(11, 19); } catch { return '—'; }
  }

  /* ---------- gate ---------- */
  $('gateForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('gateError').classList.add('hidden');
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
      state.token = data.token;
      sessionStorage.setItem(TOKEN_KEY, data.token);
      enterConsole();
    } catch (err) {
      const el = $('gateError');
      el.textContent = 'Network error — is the SOC server running?';
      el.classList.remove('hidden');
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
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(refreshAll, 2500);
  }

  /* ---------- tabs ---------- */
  document.querySelectorAll('.soc-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.soc-tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
      $(`panel-${tab.dataset.tab}`).classList.add('active');
    });
  });

  /* ---------- data ---------- */
  async function refreshAll() {
    const [statsRes, eventsRes, alertsRes, sessionsRes] = await Promise.all([
      api('/api/stats'),
      api('/api/events?limit=250'),
      api('/api/alerts'),
      api('/api/sessions'),
    ]);
    if (statsRes.ok) renderStats(statsRes.data.stats);
    if (eventsRes.ok) renderTraffic(eventsRes.data.events || []);
    if (alertsRes.ok) renderAlerts(alertsRes.data.alerts || []);
    if (sessionsRes.ok) renderSessions(sessionsRes.data.sessions || []);
  }

  function renderStats(s) {
    if (!s) return;
    $('stApi').textContent = s.api_events ?? 0;
    $('stDb').textContent = s.db_events ?? 0;
    $('stAlerts').textContent = s.alerts ?? 0;
    $('stCritical').textContent = s.critical ?? 0;
    $('stActors').textContent = s.actors ?? 0;
    const pill = $('alertCount');
    pill.textContent = s.alerts ?? 0;
    pill.classList.toggle('hidden', !(s.alerts > 0));
  }

  /* ---------- live traffic ---------- */
  function renderTraffic(events) {
    state.events = events;
    const stream = $('trafficStream');
    if (!events.length) {
      stream.innerHTML = '<div class="ev-row"><span class="muted">[NO TRAFFIC YET — OPEN THE BANKING PORTAL ON :5000 AND MAKE REQUESTS]</span></div>';
      return;
    }
    const frag = document.createDocumentFragment();
    for (const e of events) {
      const row = document.createElement('div');
      row.className = 'ev-row';
      const err = e.status_code >= 400;
      const apiChip = String(e.api || 'rest').toUpperCase();
      const op = e.operation ? ` • ${esc(e.operation)}` : '';
      row.innerHTML = `
        <span class="ts">${timeOf(e.ts)}</span>
        <span class="api-chip api-${apiChip === 'GRAPHQL' ? 'GRAPHQL' : 'REST'}">${apiChip}</span>
        <span class="user">${esc(e.username || 'ANON')}</span>
        <span class="ep">${esc(e.method)} ${esc(e.endpoint)}${op}</span>
        <span class="${err ? 'status-err' : 'status-ok'}">${e.status_code}</span>
        <span class="trace-tag">⌥ ${esc(String(e.trace_id).slice(0, 8))}</span>`;
      frag.appendChild(row);

      const queries = e.db_queries || [];
      for (const q of queries) {
        const sub = document.createElement('div');
        sub.className = 'db-sub';
        sub.innerHTML = `<span class="tag">SQL</span>${esc(q.template || q.query)}${q.rowCount != null ? ` <span class="trace-tag">(${q.rowCount} rows)</span>` : ''}`;
        frag.appendChild(sub);
      }
    }
    stream.innerHTML = '';
    stream.appendChild(frag);
  }

  /* ---------- alerts ---------- */
  function renderAlerts(alerts) {
    state.alerts = alerts;
    $('alertsEmpty').classList.toggle('hidden', alerts.length > 0);
    const list = $('alertsList');
    list.innerHTML = '';
    for (const a of alerts) {
      const card = document.createElement('div');
      card.className = `alert-card sev-${a.severity}`;
      const eps = (a.affected_endpoints || []).length;
      card.innerHTML = `
        <div class="alert-top">
          <span class="sev-chip">${a.severity === 'INFO' ? 'INFORMATIONAL' : `${a.severity} SEVERITY`}</span>
          <span class="type-chip">${esc(a.alert_type)}</span>
          <span class="alert-meta">
            <span>${timeOf(a.ts)}</span><span>•</span><span>${a.attempts} attempt${a.attempts > 1 ? 's' : ''}</span>
          </span>
        </div>
        <div class="alert-title">${esc(a.title)}</div>
        <div class="alert-summary">${esc(a.summary)}</div>
        <div class="alert-strip">
          <span>Actor: <strong>${esc(a.username || '—')}</strong></span>
          <span>Endpoints touched: <strong>${eps}</strong></span>
          ${a.is_cross_functional ? '<span class="cross-flag">⚑ CROSS-FUNCTIONAL MOVEMENT</span>' : ''}
          <span>Trace: <strong>${esc(String(a.evidence?.traceId || '').slice(0, 8))}</strong></span>
        </div>
        <div class="alert-actions">
          <button class="btn brain" data-act="path" type="button">Attack Path</button>
          <button class="btn ghost" data-act="evidence" type="button">Evidence</button>
        </div>`;
      card.querySelector('[data-act="path"]').addEventListener('click', () => openPath(a));
      card.querySelector('[data-act="evidence"]').addEventListener('click', () => openEvidence(a));
      list.appendChild(card);
    }
  }

  /* ---------- attack path modal ---------- */
  function openPath(a) {
    $('pathTitle').textContent = a.title;
    $('pathSub').textContent = `${a.alert_type} • ${a.severity} • trace ${String(a.evidence?.traceId || '').slice(0, 8)}`;
    const ap = a.attack_path || {};
    const nodes = ap.nodes || [];
    const grid = $('pathNodes');
    grid.innerHTML = '';
    nodes.forEach((n, i) => {
      const node = document.createElement('div');
      node.className = 'path-node';
      node.innerHTML = `
        <span class="ptype ${esc(n.type)}">${esc(n.type)}</span>
        <div class="plabel2">${esc(n.label)}</div>
        <div class="pdetail">${esc(n.details)}</div>`;
      grid.appendChild(node);
    });
    const steps = ap.steps || [];
    const stepsEl = $('pathSteps');
    stepsEl.innerHTML = '';
    steps.forEach((s) => {
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
    });
    $('pathModal').classList.remove('hidden');
  }
  $('pathClose').addEventListener('click', () => $('pathModal').classList.add('hidden'));
  $('pathModal').addEventListener('click', (e) => { if (e.target === $('pathModal')) $('pathModal').classList.add('hidden'); });

  function openEvidence(a) {
    $('evTitle').textContent = a.title;
    $('evJson').textContent = JSON.stringify({
      alert: { id: a.id, type: a.alert_type, severity: a.severity, attempts: a.attempts, crossFunctional: a.is_cross_functional },
      affectedEndpoints: a.affected_endpoints,
      evidence: a.evidence,
      attackPathSteps: a.attack_path?.steps,
    }, null, 2);
    $('evModal').classList.remove('hidden');
  }
  $('evClose').addEventListener('click', () => $('evModal').classList.add('hidden'));
  $('evModal').addEventListener('click', (e) => { if (e.target === $('evModal')) $('evModal').classList.add('hidden'); });

  /* ---------- sessions ---------- */
  function renderSessions(sessions) {
    const list = $('sessionsList');
    list.innerHTML = '';
    if (!sessions.length) {
      list.innerHTML = '<span class="muted mono" style="font-size:11px">[NO SESSIONS YET]</span>';
      return;
    }
    for (const s of sessions) {
      const card = document.createElement('div');
      card.className = 'session-card';
      card.innerHTML = `
        <div class="name">${esc(s.username)}</div>
        <div class="meta">actor #${s.actor_id} • ${s.api_events} API events • ${s.distinct_endpoints} endpoint classes<br/>last seen ${timeOf(s.last_seen)}</div>`;
      card.addEventListener('click', () => openTimeline(s));
      list.appendChild(card);
    }
  }

  async function openTimeline(s) {
    const { ok, data } = await api(`/api/sessions/${s.actor_id}/timeline`);
    if (!ok) return;
    $('timelineBox').classList.remove('hidden');
    $('timelineTitle').textContent = `Loopback timeline — ${s.username} (actor #${s.actor_id})`;
    const tl = $('timeline');
    tl.innerHTML = '';
    for (const e of (data.timeline || []).slice().reverse()) {
      const row = document.createElement('div');
      row.className = 'tl-row';
      row.innerHTML = `
        <span class="ts">${timeOf(e.ts)}</span>
        <span class="ep">${esc(e.method)} ${esc(e.endpoint)} → HTTP ${e.status_code}</span>
        <span class="trace">trace ${esc(String(e.trace_id).slice(0, 8))}</span>`;
      tl.appendChild(row);
      for (const q of e.db_queries || []) {
        const sql = document.createElement('div');
        sql.className = 'tl-sql';
        sql.textContent = `↳ SQL ${q.template || q.query}`;
        tl.appendChild(sql);
      }
    }
  }
  $('timelineClose').addEventListener('click', () => $('timelineBox').classList.add('hidden'));

  /* ---------- clear ---------- */
  $('clearBtn').addEventListener('click', async () => {
    if (!confirm('Clear all SOC events and alerts?')) return;
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
