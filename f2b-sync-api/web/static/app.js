// ── Token management ────────────────────────────────────────────────────────

function getToken() {
  return localStorage.getItem('access_token');
}

function getRefreshToken() {
  return localStorage.getItem('refresh_token');
}

function setTokens(access, refresh) {
  localStorage.setItem('access_token', access);
  if (refresh) localStorage.setItem('refresh_token', refresh);
}

function clearTokens() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
}

function logout() {
  clearTokens();
  window.location.href = '/';
}

function requireAuth() {
  if (!getToken()) {
    window.location.href = '/';
  }
}

// ── Token refresh ────────────────────────────────────────────────────────────

async function refreshAccessToken() {
  const rt = getRefreshToken();
  if (!rt) throw new Error('No refresh token');
  const res = await fetch('/api/v1/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: rt }),
  });
  if (!res.ok) {
    clearTokens();
    window.location.href = '/';
    throw new Error('Session expired');
  }
  const data = await res.json();
  setTokens(data.access_token, null);
  return data.access_token;
}

// ── API helpers ──────────────────────────────────────────────────────────────

async function apiFetch(url, options = {}, retry = true) {
  const token = getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  const res = await fetch(url, { ...options, headers });

  if (res.status === 401 && retry) {
    try {
      await refreshAccessToken();
      return apiFetch(url, options, false);
    } catch {
      clearTokens();
      window.location.href = '/';
      throw new Error('Session expired');
    }
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const err = await res.json();
      detail = err.detail || JSON.stringify(err);
    } catch {}
    throw new Error(detail);
  }

  if (res.status === 204) return null;
  return res.json();
}

function apiGet(url) {
  return apiFetch(url, { method: 'GET' });
}

function apiPost(url, body) {
  return apiFetch(url, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

function apiDelete(url) {
  return apiFetch(url, { method: 'DELETE' });
}

// ── Toast notifications ──────────────────────────────────────────────────────

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const colors = {
    success: 'bg-success',
    danger: 'bg-danger',
    warning: 'bg-warning text-dark',
    info: 'bg-info text-dark',
  };

  const id = `toast-${Date.now()}`;
  const div = document.createElement('div');
  div.id = id;
  div.className = `toast align-items-center text-white ${colors[type] || 'bg-secondary'} border-0 show`;
  div.setAttribute('role', 'alert');
  div.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">${esc(message)}</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto"
              onclick="document.getElementById('${id}').remove()"></button>
    </div>
  `;
  container.appendChild(div);
  setTimeout(() => div.remove(), 4000);
}

// ── XSS-safe escaping ────────────────────────────────────────────────────────

function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
