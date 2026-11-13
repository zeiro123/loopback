/* Apex Trust Bank — client portal logic */
(() => {
  const $ = (id) => document.getElementById(id);
  const TOKEN_KEY = 'apex_token';

  const state = {
    token: sessionStorage.getItem(TOKEN_KEY) || null,
    user: null,
    account: null,
    transactions: [],
    convoId: null,
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
    state.convoId = null;
    sessionStorage.removeItem(TOKEN_KEY);
    $('appView').classList.add('hidden');
    $('authView').classList.remove('hidden');
    $('chatWidget').classList.add('hidden');
    $('chatPanel').classList.add('hidden');
  }

  function saveSession() { sessionStorage.setItem(TOKEN_KEY, state.token); }

  function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

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
    $('chatWidget').classList.remove('hidden');
    $('headerName').textContent = state.user.name;
    $('profileName').textContent = state.user.name;
    $('profileUsername').textContent = state.user.username;
    $('profileId').textContent = `#${state.user.id}`;
    $('profileEmail').textContent = state.user.email || '—';
    $('profilePhone').textContent = state.user.phone || '—';
    $('profileOccupation').textContent = state.user.occupation || '—';
    $('emailNew').value = state.user.email || '';
    $('emailTargetId').value = state.user.id;
    $('detailTargetId').value = state.user.id;
    $('detailPhone').value = state.user.phone || '';
    $('detailOccupation').value = state.user.occupation || '';
    $('detailAddress').value = state.user.address || '';
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

  /* ---------- tabs (lazy-load content panels) ---------- */
  document.querySelectorAll('.bank-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.bank-tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
      $(`panel-${tab.dataset.tab}`).classList.add('active');
      const which = tab.dataset.tab;
      if (which === 'blog' && !$('blogItems').children.length) loadBlog();
      if (which === 'careers' && !$('jobsItems').children.length) loadCareers();
    });
  });

  /* ---------- transactions ---------- */
  function txnRow(t) {
    const inAmount = t.type === 'DEPOSIT';
    const when = new Date(t.created_at || t.createdAt).toLocaleString();
    return `
      <td>${when}</td>
      <td><span class="type-badge type-${t.type}">${t.type}</span></td>
      <td>${escapeHtml(t.description || '')}</td>
      <td>${escapeHtml(t.to_account_number || '')}</td>
      <td class="right ${inAmount ? 'amount-in' : 'amount-out'}">${inAmount ? '+' : '−'}${zwl(t.amount).replace('ZWL ', '')}</td>`;
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
      tr.innerHTML = txnRow(t);
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

  /* ---------- blog ---------- */
  async function loadBlog() {
    const wrap = $('blogItems');
    wrap.innerHTML = '<div class="mini-txn"><span class="when">Loading posts…</span></div>';
    try {
      const { ok, data } = await api('/api/blog/posts');
      if (!ok || !data.success) { wrap.innerHTML = '<div class="mini-txn"><span class="when">Failed to load posts.</span></div>'; return; }
      wrap.innerHTML = '';
      for (const p of data.posts) {
        const el = document.createElement('div');
        el.className = 'blog-item';
        el.innerHTML = `
          <h4>${escapeHtml(p.title)}</h4>
          <p>${escapeHtml(p.excerpt || '')}</p>
          <span class="bmeta">${escapeHtml(p.author_name || '')} • ${new Date(p.published_at).toLocaleDateString()} • ${p.comment_count} feedback</span>`;
        el.addEventListener('click', () => openBlogPost(p.id));
        wrap.appendChild(el);
      }
    } catch (err) {
      wrap.innerHTML = '<div class="mini-txn"><span class="when">Network error.</span></div>';
    }
  }

  async function openBlogPost(id) {
    try {
      const { ok, data } = await api(`/api/blog/posts/${id}`);
      if (!ok || !data.success) return;
      state.blogPostId = id;
      $('blogList').classList.add('hidden');
      $('blogReader').classList.remove('hidden');
      $('blogTitle').textContent = data.post.title;
      $('blogMeta').textContent = `${data.post.author_name || 'Apex Trust'} • ${new Date(data.post.published_at).toLocaleDateString()}`;
      $('blogBody').textContent = data.post.body || '';
      renderComments(data.comments || []);
    } catch (err) { /* ignore */ }
  }

  function renderComments(comments) {
    const wrap = $('blogComments');
    wrap.innerHTML = '';
    if (!comments.length) {
      wrap.innerHTML = '<div class="comment"><span class="muted">No feedback yet — be the first.</span></div>';
      return;
    }
    for (const c of comments) {
      const el = document.createElement('div');
      el.className = 'comment';
      el.innerHTML = `<div class="cauthor">${escapeHtml(c.author_name || 'Guest')}<span class="cwhen">${new Date(c.created_at).toLocaleString()}</span></div>${escapeHtml(c.body)}`;
      wrap.appendChild(el);
    }
  }

  $('blogBack').addEventListener('click', () => {
    $('blogReader').classList.add('hidden');
    $('blogList').classList.remove('hidden');
    loadBlog();
  });

  $('commentForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = $('commentBody').value.trim();
    if (!body || !$('blogTitle').textContent) return;
    const btn = $('commentBtn');
    btn.disabled = true;
    try {
      // read the current post id from state (set when opened)
      const { ok, data } = await api(`/api/blog/posts/${state.blogPostId}/comments`, {
        method: 'POST',
        body: JSON.stringify({ body }),
      });
      if (ok && data.success) {
        $('commentBody').value = '';
        const { ok: ok2, data: data2 } = await api(`/api/blog/posts/${state.blogPostId}`);
        if (ok2 && data2.success) renderComments(data2.comments || []);
        toast('Feedback posted.');
      }
    } finally {
      btn.disabled = false;
    }
  });

  /* ---------- careers ---------- */
  async function loadCareers(q) {
    const wrap = $('jobsItems');
    wrap.innerHTML = '<div class="mini-txn"><span class="when">Loading openings…</span></div>';
    try {
      const url = q ? `/api/jobs/search?q=${encodeURIComponent(q)}` : '/api/jobs';
      const [jobsRes, appsRes] = await Promise.all([api(url), api('/api/applications/mine')]);
      wrap.innerHTML = '';
      // VULNERABLE SINK: the server reflects the raw search query back and the
      // header is rendered as HTML — a payload like <img src=x onerror=alert(1)>
      // executes here (reflected XSS the SOC ladders per attempt).
      if (q && jobsRes.ok && jobsRes.data.success) {
        $('jobSearchOut').innerHTML = `Results for: ${jobsRes.data.q} — ${jobsRes.data.count} match(es)`;
      } else if (q) {
        $('jobSearchOut').textContent = 'Search failed.';
      } else {
        $('jobSearchOut').innerHTML = '';
      }
      if (!jobsRes.ok || !jobsRes.data.success) {
        wrap.innerHTML = '<div class="mini-txn"><span class="when">Sign in to view and apply for openings.</span></div>';
        return;
      }
      for (const j of jobsRes.data.jobs) {
        const el = document.createElement('div');
        el.className = 'job-item';
        el.innerHTML = `
          <div class="job-top">
            <div>
              <h4>${escapeHtml(j.title)}</h4>
              <span class="jmeta">
                <span class="chip subtle">${escapeHtml(j.department || '')}</span>
                <span class="chip subtle">${escapeHtml(j.location || '')}</span>
                <span class="chip subtle">${escapeHtml(j.employment_type || '')}</span>
                <span class="chip">ZWL ${Number(j.salary_min).toLocaleString()} – ${Number(j.salary_max).toLocaleString()}</span>
              </span>
            </div>
            <button class="chip-btn" data-job="${j.id}" type="button">Apply</button>
          </div>
          <p class="jdesc">${escapeHtml(j.description || '')}</p>
          <div class="cover-label">Cover letter
            <textarea rows="2" placeholder="Why you? (optional)" id="cover-${j.id}"></textarea>
          </div>`;
        el.querySelector('.chip-btn').addEventListener('click', (e) => applyJob(j.id, e.target));
        wrap.appendChild(el);
      }
      renderMyApps(appsRes.ok && appsRes.data.success ? appsRes.data.applications : []);
    } catch (err) {
      wrap.innerHTML = '<div class="mini-txn"><span class="when">Network error.</span></div>';
    }
  }

  $('jobSearchForm').addEventListener('submit', (e) => {
    e.preventDefault();
    loadCareers($('jobSearchQ').value.trim());
  });

  async function applyJob(jobId, btn) {
    const cover = $(`cover-${jobId}`)?.value?.trim();
    btn.disabled = true;
    try {
      const { ok, data } = await api(`/api/jobs/${jobId}/apply`, {
        method: 'POST',
        body: JSON.stringify({ coverLetter: cover || undefined }),
      });
      if (ok && data.success) {
        toast(data.message);
        const apps = await api('/api/applications/mine');
        if (apps.ok && apps.data.success) renderMyApps(apps.data.applications);
      } else {
        toast(data.error || 'Application failed — sign in first.');
      }
    } finally {
      btn.disabled = false;
    }
  }

  function renderMyApps(apps) {
    const wrap = $('myAppsList');
    wrap.innerHTML = '';
    if (!state.token) {
      wrap.innerHTML = '<div class="mini-txn"><span class="when">Sign in to track your applications.</span></div>';
      return;
    }
    if (!apps.length) {
      wrap.innerHTML = '<div class="mini-txn"><span class="when">No applications yet — apply above.</span></div>';
      return;
    }
    for (const a of apps) {
      const el = document.createElement('div');
      el.className = 'mini-txn';
      el.innerHTML = `<span><strong>${escapeHtml(a.job_title)}</strong> <span class="when">• ${escapeHtml(a.status)}</span></span><span class="when">${new Date(a.created_at).toLocaleDateString()}</span>`;
      wrap.appendChild(el);
    }
  }

  /* ---------- support chat (floating Apex Assist widget) ---------- */
  function chatAppend(role, text) {
    const log = $('chatLog');
    const el = document.createElement('div');
    el.className = `chat-msg ${role === 'user' ? 'me' : 'bot'}`;
    el.textContent = text;
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
  }

  $('chatBubble').addEventListener('click', () => {
    const panel = $('chatPanel');
    panel.classList.toggle('hidden');
    $('chatBubble').classList.toggle('open', !panel.classList.contains('hidden'));
  });

  $('chatMin').addEventListener('click', () => {
    $('chatPanel').classList.add('hidden');
    $('chatBubble').classList.remove('open');
  });

  $('chatForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = $('chatText').value.trim();
    if (!text) return;
    chatAppend('user', text);
    $('chatText').value = '';
    try {
      const { ok, data } = await api('/api/support/chat', {
        method: 'POST',
        body: JSON.stringify({ message: text, convoId: state.convoId || undefined }),
      });
      if (ok && data.success) {
        state.convoId = data.convoId;
        chatAppend('bot', data.reply);
      } else {
        chatAppend('bot', 'The assistant is unavailable right now.');
      }
    } catch (err) {
      chatAppend('bot', 'Network error.');
    }
  });

  /* ---------- profile / email / details ---------- */
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

  $('detailsForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideBanner('emailBanner');
    const btn = $('detailsBtn');
    btn.disabled = true;
    try {
      const targetId = $('detailTargetId').value.trim() || state.user.id;
      const { ok, data } = await api(`/api/users/${targetId}/details`, {
        method: 'PUT',
        body: JSON.stringify({
          phone: $('detailPhone').value.trim() || undefined,
          occupation: $('detailOccupation').value.trim() || undefined,
          address: $('detailAddress').value.trim() || undefined,
        }),
      });
      if (!ok || !data.success) {
        showBanner('emailBanner', 'error', data.error || 'Details update failed.');
        return;
      }
      showBanner('emailBanner', 'success', data.message);
      if (Number(targetId) === state.user.id) {
        state.user = { ...state.user, ...data.user };
        $('profilePhone').textContent = data.user.phone || '—';
        $('profileOccupation').textContent = data.user.occupation || '—';
      }
      toast(data.message);
    } catch (err) {
      showBanner('emailBanner', 'error', 'Network error.');
    } finally {
      btn.disabled = false;
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
      if (Number(id) === state.user.id) state.user.apiKey = data.apiKey;
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
})();
