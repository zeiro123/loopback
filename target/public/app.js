/* Apex Trust Bank — client portal logic */
(() => {
  const $ = (id) => document.getElementById(id);
  const TOKEN_KEY = 'apex_token';

  const state = {
    token: sessionStorage.getItem(TOKEN_KEY) || null,
    user: null,
    account: null,
    transactions: [],
  };

  /* ---------- helpers ---------- */
  async function api(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    const res = await fetch(path, { ...opts, headers });
    let data = {};
    try { data = await res.json(); } catch { /* no body */ }
    if (res.status === 401 && state.token) { clearSession(); }
    return { ok: res.ok, status: res.status, data };
  }

  function zwl(n) {
    return `ZWL ${Number(n || 0).toLocaleString('en-ZW', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }

  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.add('hidden'), 3200);
  }

  function showBanner(id, type, msg) {
    const el = $(id);
    el.className = `banner ${type}`;
    el.textContent = msg;
  }
  function hideBanner(id) { $(id).classList.add('hidden'); }

  function clearSession() {
    state.token = null;
    state.user = null;
    state.account = null;
    state.transactions = [];
    sessionStorage.removeItem(TOKEN_KEY);
    $('appView').classList.add('hidden');
    $('authView').classList.remove('hidden');
  }

  function saveSession() { sessionStorage.setItem(TOKEN_KEY, state.token); }

  /* ---------- auth forms ---------- */
  $('tabLogin').addEventListener('click', () => switchAuth('login'));
  $('tabRegister').addEventListener('click', () => switchAuth('register'));
  function switchAuth(which) {
    const login = which === 'login';
    $('tabLogin').classList.toggle('active', login);
    $('tabRegister').classList.toggle('active', !login);
    $('loginForm').classList.toggle('hidden', !login);
    $('registerForm').classList.toggle('hidden', login);
    hideBanner('loginError');
    hideBanner('registerError');
  }

  $('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideBanner('loginError');
    const btn = $('loginBtn');
    btn.disabled = true;
    btn.textContent = 'Signing in…';
    try {
      const { ok, data } = await api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: $('loginUsername').value.trim(), password: $('loginPassword').value.trim() }),
      });
      if (!ok || !data.success) {
        showBanner('loginError', 'error', data.error || 'Login failed.');
        return;
      }
      state.token = data.token;
      state.user = data.user;
      state.account = data.account;
      saveSession();
      enterApp();
    } catch (err) {
      showBanner('loginError', 'error', 'Network error — is the bank server running?');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign In';
    }
  });

  $('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideBanner('registerError');
    const btn = $('registerBtn');
    btn.disabled = true;
    btn.textContent = 'Opening account…';
    try {
      const { ok, data } = await api('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          name: $('regName').value.trim(),
          username: $('regUsername').value.trim(),
          email: $('regEmail').value.trim(),
          password: $('regPassword').value,
        }),
      });
      if (!ok || !data.success) {
        showBanner('registerError', 'error', data.error || 'Account opening failed.');
        return;
      }
      toast(data.message);
      state.token = data.token;
      state.user = data.user;
      state.account = data.account;
      saveSession();
      enterApp();
    } catch (err) {
      showBanner('registerError', 'error', 'Network error — is the bank server running?');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Open My Account';
    }
  });

  $('logoutBtn').addEventListener('click', async () => {
    try { await api('/api/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
    clearSession();
  });

  /* ---------- app shell ---------- */
  function enterApp() {
    $('authView').classList.add('hidden');
    $('appView').classList.remove('hidden');
    $('headerName').textContent = state.user.name;
    $('profileName').textContent = state.user.name;
    $('profileUsername').textContent = state.user.username;
    $('profileId').textContent = `#${state.user.id}`;
    $('profileEmail').textContent = state.user.email || '—';
    $('emailNew').value = state.user.email || '';
    $('emailTargetId').value = state.user.id;
    $('keyUserId').value = state.user.id;
    $('stmtAccount').value = state.account?.accountNumber || '';
    $('txnAccount').value = state.account?.accountNumber || '';
    $('transferTo').value = '';
    renderBalance();
    loadTransactions(state.account?.accountNumber, { silent: true });
  }

  function renderBalance() {
    if (!state.account) return;
    $('dashBalance').textContent = zwl(state.account.balance);
    $('dashAccount').textContent = state.account.accountNumber;
    $('dashCurrency').textContent = state.account.currency || 'ZWL';
    $('statOwner').textContent = state.user.name;
    $('statType').textContent = state.account.type || 'CHECKING';
  }

  /* ---------- tabs ---------- */
  document.querySelectorAll('.bank-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.bank-tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
      $(`panel-${tab.dataset.tab}`).classList.add('active');
    });
  });

  /* ---------- transactions ---------- */
  async function loadTransactions(accountNumber, { silent = false, bannerId = 'txnBanner' } = {}) {
    if (!accountNumber) return;
    try {
      const { ok, data } = await api(`/api/accounts/${encodeURIComponent(accountNumber)}/transactions`);
      if (!ok || !data.success) {
        if (!silent) showBanner(bannerId, 'error', data.error || 'Failed to load transactions.');
        return;
      }
      hideBanner(bannerId);
      if (silent || accountNumber === state.account?.accountNumber) {
        state.transactions = data.transactions || [];
        $('statTxCount').textContent = state.transactions.length;
        renderBalance();
        renderRecent();
      }
      renderMainTxns(data);
    } catch (err) {
      if (!silent) showBanner(bannerId, 'error', 'Network error.');
    }
  }

  function renderMainTxns(data) {
    const body = $('txnBody');
    body.innerHTML = '';
    const txns = data.transactions || [];
    if (!txns.length) {
      body.innerHTML = '<tr><td colspan="5" class="empty">No transactions recorded for this account.</td></tr>';
      return;
    }
    for (const t of txns) {
      const tr = document.createElement('tr');
      const inAmount = t.type === 'DEPOSIT';
      const when = new Date(t.created_at).toLocaleString();
      tr.innerHTML = `
        <td>${when}</td>
        <td><span class="type-badge type-${t.type}">${t.type}</span></td>
        <td>${escapeHtml(t.description || '')}</td>
        <td>${escapeHtml(t.to_account_number || '')}</td>
        <td class="right ${inAmount ? 'amount-in' : 'amount-out'}">${inAmount ? '+' : '−'}${zwl(t.amount).replace('ZWL ', '')}</td>`;
      body.appendChild(tr);
    }
  }

  function renderRecent() {
    const wrap = $('dashRecent');
    wrap.innerHTML = '';
    const recent = state.transactions.slice(0, 5);
    if (!recent.length) {
      wrap.innerHTML = '<div class="mini-txn"><span class="when">No activity yet — send your first transfer.</span></div>';
      return;
    }
    for (const t of recent) {
      const el = document.createElement('div');
      el.className = 'mini-txn';
      const inAmount = t.type === 'DEPOSIT';
      el.innerHTML = `
        <span><strong>${inAmount ? '+' : '−'}${zwl(t.amount).replace('ZWL ', '')}</strong> <span class="when">• ${escapeHtml(t.description || t.type)}</span></span>
        <span class="when">${new Date(t.created_at).toLocaleDateString()}</span>`;
      wrap.appendChild(el);
    }
  }

  $('txnLoad').addEventListener('click', () => loadTransactions($('txnAccount').value.trim(), { bannerId: 'txnBanner' }));

  /* ---------- transfer ---------- */
  document.querySelectorAll('.btn-chip').forEach((c) => {
    c.addEventListener('click', () => { $('transferAmount').value = c.dataset.amt; });
  });

  $('transferForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideBanner('transferBanner');
    const btn = $('transferBtn');
    btn.disabled = true;
    btn.textContent = 'Processing…';
    try {
      const { ok, data } = await api('/api/transfers', {
        method: 'POST',
        body: JSON.stringify({
          toAccountNumber: $('transferTo').value.trim(),
          amount: parseFloat($('transferAmount').value),
          memo: $('transferMemo').value.trim() || undefined,
        }),
      });
      if (!ok || !data.success) {
        showBanner('transferBanner', 'error', data.error || 'Transfer failed.');
        return;
      }
      showBanner('transferBanner', 'success', data.message);
      if (state.account) state.account.balance = data.updatedBalance;
      renderBalance();
      $('transferAmount').value = '';
      $('transferMemo').value = '';
      loadTransactions(state.account?.accountNumber, { silent: true });
      toast(data.message);
    } catch (err) {
      showBanner('transferBanner', 'error', 'Network error.');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Send Transfer';
    }
  });

  /* ---------- statements ---------- */
  $('stmtDownload').addEventListener('click', async () => {
    hideBanner('stmtBanner');
    const accNum = $('stmtAccount').value.trim();
    if (!accNum) { showBanner('stmtBanner', 'error', 'Enter an account number.'); return; }
    const btn = $('stmtDownload');
    btn.disabled = true;
    btn.textContent = 'Downloading…';
    try {
      const { ok, data } = await api(`/api/statements/${encodeURIComponent(accNum)}`);
      if (!ok || !data.success) {
        showBanner('stmtBanner', 'error', data.error || 'Failed to fetch statement.');
        return;
      }
      hideBanner('stmtBanner');
      const s = data.statement;
      $('stmtHolder').innerHTML = `
        <strong>${escapeHtml(s.accountHolder.name)}</strong> — Account ${escapeHtml(s.account.accountNumber)}<br/>
        <strong>Registered address:</strong> ${escapeHtml(s.accountHolder.address)}<br/>
        <strong>Ledger balance:</strong> ${zwl(s.account.balance)} (${escapeHtml(s.account.currency)})`;
      const preview = $('stmtPreview');
      preview.textContent = data.textDocument;
      preview.classList.remove('hidden');
      const blob = new Blob([data.textDocument], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Statement_${accNum}_${new Date().toISOString().slice(0, 10)}.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast(`Statement ${s.statementId} downloaded for ${accNum}.`);
    } catch (err) {
      showBanner('stmtBanner', 'error', 'Network error.');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Download Statement';
    }
  });

  /* ---------- profile / email ---------- */
  $('emailForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideBanner('emailBanner');
    try {
      const targetId = $('emailTargetId').value.trim() || state.user.id;
      const { ok, data } = await api(`/api/users/${targetId}/email`, {
        method: 'PUT',
        body: JSON.stringify({ email: $('emailNew').value.trim() }),
      });
      if (!ok || !data.success) {
        showBanner('emailBanner', 'error', data.error || 'Email update failed.');
        return;
      }
      showBanner('emailBanner', 'success', data.message);
      state.user.email = data.user.email;
      $('profileEmail').textContent = data.user.email;
      $('emailNew').value = data.user.email;
      toast(data.message);
    } catch (err) {
      showBanner('emailBanner', 'error', 'Network error.');
    }
  });

  /* ---------- API keys ---------- */
  $('keyLoad').addEventListener('click', async () => {
    hideBanner('keyBanner');
    const id = $('keyUserId').value.trim();
    if (!id) { showBanner('keyBanner', 'error', 'Enter a client ID.'); return; }
    try {
      const { ok, data } = await api(`/api/users/${id}/apikey`);
      if (!ok || !data.success) {
        showBanner('keyBanner', 'error', data.error || 'Unable to retrieve credentials.');
        return;
      }
      hideBanner('keyBanner');
      $('keyBox').classList.remove('hidden');
      $('keyValue').textContent = data.apiKey;
      if (Number(id) === state.user.id) {
        state.user.apiKey = data.apiKey;
      }
    } catch (err) {
      showBanner('keyBanner', 'error', 'Network error.');
    }
  });

  $('keyCopy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('keyValue').textContent);
      toast('API key copied to clipboard.');
    } catch { toast('Copy failed — select the key manually.'); }
  });

  /* ---------- boot: restore session ---------- */
  (async () => {
    if (!state.token) return;
    const { ok, data } = await api('/api/auth/me');
    if (ok && data.success) {
      state.user = data.user;
      state.account = data.account;
      enterApp();
    } else {
      clearSession();
    }
  })();

  function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
})();
