import crypto from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import express from 'express';

loadDotEnv();

const app = express();
const port = Number(process.env.PORT ?? 4025);
const authServerUrl = (process.env.AUTH_SERVER_URL ?? 'https://mfa.node-hub.com').replace(/\/$/, '');
const authAppToken = process.env.AUTH_APP_TOKEN;
const authTenantAdminToken = process.env.AUTH_TENANT_ADMIN_TOKEN;
const authTenantId = process.env.AUTH_TENANT_ID ?? 'default';
const adminUserHint = process.env.AUTH_ADMIN_USER_HINT ?? 'admin@example.local';
const sessionSecret = process.env.SESSION_SECRET ?? authAppToken ?? 'change-me';
const dataPath = resolve(process.env.DATA_PATH ?? '.data/users.json');

app.use(express.urlencoded({ extended: false }));

app.get('/', (_req, res) => res.send(page('<h1>Express complete</h1><p><a href="/admin">Admin</a> - <a href="/app">User app</a></p>')));

app.get('/admin', async (req, res, next) => {
  try {
    if (readSession(req, 'admin_session')?.ok) return res.redirect('/admin/users');
    const challengeId = req.query.challenge?.toString();
    if (!challengeId) return res.send(page(`<h1>Admin access</h1><p><code>${escapeHtml(adminUserHint)}</code></p><form method="post" action="/admin/start"><button>Request access</button></form>`));
    const challenge = await getChallenge(challengeId);
    if (challenge.status === 'approved') {
      res.setHeader('set-cookie', createSession('admin_session', { ok: true }, '/admin'));
      return res.redirect('/admin/users');
    }
    res.send(page(renderChallenge(challenge, '/admin')));
  } catch (error) {
    next(error);
  }
});

app.post('/admin/start', async (_req, res, next) => {
  try {
    const challenge = await createChallenge(adminUserHint, 'Express complete admin');
    res.redirect(`/admin?challenge=${encodeURIComponent(challenge.id)}`);
  } catch (error) {
    next(error);
  }
});

app.get('/admin/logout', (_req, res) => {
  res.setHeader('set-cookie', clearSession('admin_session', '/admin'));
  res.redirect('/');
});

app.get('/admin/users', requireAdmin, (req, res) => {
  const rows = readUsers().map((user) => `<tr><td>${escapeHtml(user.email)}</td><td>${escapeHtml(user.name)}</td><td>${escapeHtml(user.status)}</td><td>${user.token ? `<a href="/admin/invite/${encodeURIComponent(user.token)}">Invite</a>` : 'Already enrolled'}</td></tr>`).join('');
  res.send(page(`<h1>Users</h1><p><a href="/admin/logout">Logout</a></p><h2>Add existing enrolled user</h2><form method="post"><input type="hidden" name="action" value="existing"><input name="email" type="email" placeholder="email" required> <input name="name" placeholder="name" required> <button>Add local user</button></form><h2>Create user and enrollment invite</h2><form method="post"><input type="hidden" name="action" value="enroll"><input name="email" type="email" placeholder="email" required> <input name="name" placeholder="name" required> <button>Create + enroll</button></form><table>${rows}</table>`));
});

app.post('/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const email = String(req.body.email ?? '').trim().toLowerCase();
    const name = String(req.body.name ?? '').trim();
    const action = String(req.body.action ?? 'enroll');
    const users = readUsers();
    if (!email || !name) return res.status(400).send(page('<h1>Missing email or name</h1>'));
    if (users.some((user) => user.email === email)) return res.status(409).send(page('<h1>User already exists</h1>'));
    if (action === 'existing') {
      users.push({ id: crypto.randomUUID(), email, name, status: 'active', createdAt: new Date().toISOString() });
      writeUsers(users);
      return res.redirect('/admin/users');
    }
    const enrollmentUrl = await createEnrollment(email);
    const token = crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', '');
    users.push({ id: crypto.randomUUID(), email, name, status: 'invited', enrollmentUrl, token, createdAt: new Date().toISOString() });
    writeUsers(users);
    res.redirect(`/admin/invite/${encodeURIComponent(token)}`);
  } catch (error) {
    next(error);
  }
});

app.get('/admin/invite/:token', requireAdmin, (req, res) => {
  const user = readUsers().find((candidate) => candidate.token === req.params.token);
  if (!user) return res.status(404).send(page('<h1>Invite not found</h1>'));
  const inviteUrl = `${req.protocol}://${req.get('host')}/invite/${encodeURIComponent(user.token)}`;
  res.send(page(`<h1>Invitation</h1><p>User: <code>${escapeHtml(user.email)}</code></p><p><a href="${escapeHtml(inviteUrl)}">${escapeHtml(inviteUrl)}</a></p>`));
});

app.get('/invite/:token', (req, res) => {
  const user = readUsers().find((candidate) => candidate.token === req.params.token);
  if (!user) return res.status(404).send(page('<h1>Invite not found</h1>'));
  if (!user.enrollmentUrl) return res.status(404).send(page('<h1>No enrollment invite for this user</h1>'));
  const qr = `https://api.qrserver.com/v1/create-qr-code/?size=280x280&data=${encodeURIComponent(user.enrollmentUrl)}`;
  res.send(page(`<h1>Invite ${escapeHtml(user.name)}</h1><p>Scan this enrollment QR code.</p><p><img src="${qr}" width="280" height="280" alt="Enrollment QR"></p><p><a href="/app?user=${encodeURIComponent(user.email)}">Open app</a></p>`));
});

app.get('/app', async (req, res, next) => {
  try {
    const session = readSession(req, 'user_session');
    if (session?.email) return res.send(page(`<h1>User app</h1><p>Access granted for <code>${escapeHtml(session.email)}</code>.</p><p><a href="/app/logout">Logout</a></p>`));
    const challengeId = req.query.challenge?.toString();
    const email = req.query.user?.toString();
    if (challengeId && email) {
      const challenge = await getChallenge(challengeId);
      if (challenge.status === 'approved') {
        activateUser(email);
        res.setHeader('set-cookie', createSession('user_session', { email }, '/app'));
        return res.redirect('/app');
      }
      return res.send(page(renderChallenge(challenge, '/app')));
    }
    res.send(page(`<h1>User access</h1><form method="post" action="/app/start"><input name="email" type="email" value="${escapeHtml(email ?? '')}" required> <button>Request access</button></form>`));
  } catch (error) {
    next(error);
  }
});

app.post('/app/start', async (req, res, next) => {
  try {
    const email = String(req.body.email ?? '').trim().toLowerCase();
    const user = readUsers().find((candidate) => candidate.email === email && candidate.status !== 'disabled');
    if (!user) return res.status(404).send(page('<h1>User not found</h1>'));
    const challenge = await createChallenge(email, 'Express complete user app');
    res.redirect(`/app?challenge=${encodeURIComponent(challenge.id)}&user=${encodeURIComponent(email)}`);
  } catch (error) {
    next(error);
  }
});

app.get('/app/logout', (_req, res) => {
  res.setHeader('set-cookie', clearSession('user_session', '/app'));
  res.redirect('/');
});

app.use((error, _req, res, _next) => res.status(500).send(page(`<h1>Error</h1><pre>${escapeHtml(error.message)}</pre>`)));

app.listen(port, () => console.log(`Express complete listening on http://localhost:${port}`));

function requireAdmin(req, res, next) {
  if (!readSession(req, 'admin_session')?.ok) return res.redirect('/admin');
  next();
}

async function createChallenge(userHint, resource) {
  if (!authAppToken) throw new Error('AUTH_APP_TOKEN is required.');
  const response = await fetch(`${authServerUrl}/api/challenges`, {
    method: 'POST',
    headers: { authorization: `Bearer ${authAppToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ userHint, resource, mode: 'push_with_number', location: 'Express complete' }),
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

function renderChallenge(challenge, retryPath) {
  return `<h1>MFA required</h1>${challenge.numberMatch ? `<p>Confirm: <strong style="font-size:42px">${escapeHtml(challenge.numberMatch)}</strong></p>` : ''}<p>Status: <code>${escapeHtml(challenge.status)}</code></p><script>setTimeout(() => location.reload(), 2000)</script><p><a href="${retryPath}">Cancel</a></p>`;
}

function page(body) {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Express complete</title><body>${body}</body></html>`;
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
