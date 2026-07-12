import crypto from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';

loadDotEnv();

const port = Number(process.env.PORT ?? 4024);
const authServerUrl = (process.env.AUTH_SERVER_URL ?? 'https://mfa.node-hub.com').replace(/\/$/, '');
const authAppToken = process.env.AUTH_APP_TOKEN;
const authTenantAdminToken = process.env.AUTH_TENANT_ADMIN_TOKEN;
const authTenantId = process.env.AUTH_TENANT_ID ?? 'default';
const adminUserHint = process.env.AUTH_ADMIN_USER_HINT ?? 'admin@example.local';
const sessionSecret = process.env.SESSION_SECRET ?? authAppToken ?? 'change-me';
const dataPath = resolve(process.env.DATA_PATH ?? '.data/users.json');

createServer((req, res) => {
  handle(req, res).catch((error) => send(res, 500, `<h1>Error</h1><pre>${escapeHtml(error.message)}</pre>`));
}).listen(port, () => console.log(`JS complete listening on http://localhost:${port}`));

async function handle(req, res) {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? `localhost:${port}`}`);

  if (url.pathname === '/') {
    send(res, 200, '<h1>JS complete</h1><p><a href="/admin">Admin</a> - <a href="/app">User app</a></p>');
    return;
  }

  if (url.pathname === '/admin') {
    if (readSession(req, 'admin_session')?.ok) return redirect(res, '/admin/users');

    const challengeId = url.searchParams.get('challenge');
    if (!challengeId) {
      send(res, 200, `<h1>Admin access</h1><p>Admin MFA user: <code>${escapeHtml(adminUserHint)}</code></p><form method="post" action="/admin/start"><button>Request admin access</button></form>`);
      return;
    }

    const challenge = await getChallenge(challengeId);
    if (challenge.status === 'approved') {
      redirect(res, '/admin/users', { 'set-cookie': createSession('admin_session', { ok: true }, '/admin') });
      return;
    }

    sendChallenge(res, challenge, '/admin');
    return;
  }

  if (url.pathname === '/admin/start' && req.method === 'POST') {
    const challenge = await createChallenge(adminUserHint, 'JS complete admin');
    redirect(res, `/admin?challenge=${encodeURIComponent(challenge.id)}`);
    return;
  }

  if (url.pathname === '/admin/logout') {
    redirect(res, '/', { 'set-cookie': clearSession('admin_session', '/admin') });
    return;
  }

  if (url.pathname === '/admin/users') {
    if (!readSession(req, 'admin_session')?.ok) return redirect(res, '/admin');

    if (req.method === 'POST') {
      const form = await readForm(req);
      const email = String(form.email ?? '').trim().toLowerCase();
      const name = String(form.name ?? '').trim();
      if (!email || !name) return send(res, 400, '<h1>Missing email or name</h1>');

      const users = readUsers();
      if (users.some((user) => user.email === email)) return send(res, 409, '<h1>User already exists</h1>');

      const enrollmentUrl = await createEnrollment(email);
      const token = crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '');
      users.push({ id: crypto.randomUUID(), email, name, status: 'invited', enrollmentUrl, token, createdAt: new Date().toISOString() });
      writeUsers(users);
      redirect(res, `/admin/invite?token=${encodeURIComponent(token)}`);
      return;
    }

    const rows = readUsers().map((user) => `<tr><td>${escapeHtml(user.email)}</td><td>${escapeHtml(user.name)}</td><td>${escapeHtml(user.status)}</td><td><a href="/admin/invite?token=${encodeURIComponent(user.token)}">Invite</a></td></tr>`).join('');
    send(res, 200, `<h1>Users</h1><p><a href="/admin/logout">Logout</a></p><form method="post"><input name="email" type="email" placeholder="email" required> <input name="name" placeholder="name" required> <button>Create + enroll</button></form><table>${rows}</table>`);
    return;
  }

  if (url.pathname === '/admin/invite') {
    if (!readSession(req, 'admin_session')?.ok) return redirect(res, '/admin');
    const user = readUsers().find((candidate) => candidate.token === url.searchParams.get('token'));
    if (!user) return send(res, 404, '<h1>Invite not found</h1>');
    const inviteUrl = `${baseUrl(req)}/invite/${encodeURIComponent(user.token)}`;
    send(res, 200, `<h1>Invitation</h1><p>User: <code>${escapeHtml(user.email)}</code></p><p><a href="${escapeHtml(inviteUrl)}">${escapeHtml(inviteUrl)}</a></p>`);
    return;
  }

  if (url.pathname.startsWith('/invite/')) {
    const token = decodeURIComponent(url.pathname.split('/')[2] ?? '');
    const user = readUsers().find((candidate) => candidate.token === token);
    if (!user) return send(res, 404, '<h1>Invite not found</h1>');
    const qr = `https://api.qrserver.com/v1/create-qr-code/?size=280x280&data=${encodeURIComponent(user.enrollmentUrl)}`;
    send(res, 200, `<h1>Invite ${escapeHtml(user.name)}</h1><p>Scan this enrollment QR code in Node-hud Authenticator.</p><p><img src="${qr}" width="280" height="280" alt="Enrollment QR"></p><p><a href="/app?user=${encodeURIComponent(user.email)}">Open protected app</a></p>`);
    return;
  }

  if (url.pathname === '/app') {
    const session = readSession(req, 'user_session');
    if (session?.email) return send(res, 200, `<h1>User app</h1><p>Access granted for <code>${escapeHtml(session.email)}</code>.</p><p><a href="/app/logout">Logout</a></p>`);

    const challengeId = url.searchParams.get('challenge');
    const email = url.searchParams.get('user');
    if (challengeId && email) {
      const challenge = await getChallenge(challengeId);
      if (challenge.status === 'approved') {
        activateUser(email);
        redirect(res, '/app', { 'set-cookie': createSession('user_session', { email }, '/app') });
        return;
      }
      return sendChallenge(res, challenge, '/app');
    }

    send(res, 200, `<h1>User access</h1><form method="post" action="/app/start"><input name="email" type="email" value="${escapeHtml(email ?? '')}" required><button>Request access</button></form>`);
    return;
  }

  if (url.pathname === '/app/start' && req.method === 'POST') {
    const form = await readForm(req);
    const email = String(form.email ?? '').trim().toLowerCase();
    const user = readUsers().find((candidate) => candidate.email === email && candidate.status !== 'disabled');
    if (!user) return send(res, 404, '<h1>User not found</h1>');
    const challenge = await createChallenge(email, 'JS complete user app');
    redirect(res, `/app?challenge=${encodeURIComponent(challenge.id)}&user=${encodeURIComponent(email)}`);
    return;
  }

  if (url.pathname === '/app/logout') {
    redirect(res, '/', { 'set-cookie': clearSession('user_session', '/app') });
    return;
  }

  send(res, 404, '<h1>Not found</h1>');
}

async function createChallenge(userHint, resource) {
  if (!authAppToken) throw new Error('AUTH_APP_TOKEN is required.');
  const response = await fetch(`${authServerUrl}/api/challenges`, {
    method: 'POST',
    headers: { authorization: `Bearer ${authAppToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ userHint, resource, mode: 'push_with_number', location: 'JS complete' }),
  });
  if (!response.ok) throw new Error(`Challenge failed: ${response.status} ${await response.text()}`);
  return (await response.json()).challenge;
}

async function getChallenge(id) {
  const response = await fetch(`${authServerUrl}/api/challenges/${encodeURIComponent(id)}`);
  if (!response.ok) throw new Error(`Challenge read failed: ${response.status}`);
  return (await response.json()).challenge;
}

async function createEnrollment(email) {
  if (!authTenantAdminToken) throw new Error('AUTH_TENANT_ADMIN_TOKEN is required.');
  const response = await fetch(`${authServerUrl}/api/enrollments/new?tenant=${encodeURIComponent(authTenantId)}&user=${encodeURIComponent(email)}`, {
    headers: { authorization: `Bearer ${authTenantAdminToken}` },
  });
  if (!response.ok) throw new Error(`Enrollment failed: ${response.status} ${await response.text()}`);
  return (await response.json()).enrollmentUrl;
}

function readUsers() {
  return existsSync(dataPath) ? JSON.parse(readFileSync(dataPath, 'utf8')) : [];
}

function writeUsers(users) {
  mkdirSync(dirname(dataPath), { recursive: true });
  writeFileSync(dataPath, `${JSON.stringify(users, null, 2)}\n`, 'utf8');
}

function activateUser(email) {
  const users = readUsers();
  const user = users.find((candidate) => candidate.email === email);
  if (user?.status === 'invited') {
    user.status = 'active';
    writeUsers(users);
  }
}

async function readForm(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')).entries());
}

function sendChallenge(res, challenge, retryPath) {
  send(res, 200, `<h1>MFA required</h1>${challenge.numberMatch ? `<p>Confirm: <strong style="font-size:42px">${escapeHtml(challenge.numberMatch)}</strong></p>` : ''}<p>Status: <code>${escapeHtml(challenge.status)}</code></p><script>setTimeout(() => location.reload(), 2000)</script><p><a href="${retryPath}">Cancel</a></p>`);
}

function createSession(name, data, path) {
  const payload = Buffer.from(JSON.stringify({ ...data, expiresAt: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  return `${name}=${encodeURIComponent(`${payload}.${signature}`)}; HttpOnly; SameSite=Lax; Path=${path}; Max-Age=28800`;
}

function readSession(req, name) {
  const raw = req.headers.cookie?.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1);
  if (!raw) return undefined;
  const [payload, signature] = decodeURIComponent(raw).split('.');
  const expected = crypto.createHmac('sha256', sessionSecret).update(payload).digest('base64url');
  if (!signature || Buffer.byteLength(signature) !== Buffer.byteLength(expected) || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return undefined;
  const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  return session.expiresAt > Date.now() ? session : undefined;
}

function clearSession(name, path) {
  return `${name}=; HttpOnly; SameSite=Lax; Path=${path}; Max-Age=0`;
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { location, ...headers });
  res.end();
}

function send(res, status, body) {
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>JS complete</title><body>${body}</body></html>`;
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
}

function baseUrl(req) {
  return `http://${req.headers.host ?? `localhost:${port}`}`;
}

function escapeHtml(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');
}

function loadDotEnv(path = resolve(process.cwd(), '.env')) {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator === -1) continue;
    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim().replace(/^['"]|['"]$/g, '');
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}
