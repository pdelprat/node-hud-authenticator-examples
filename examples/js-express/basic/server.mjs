import crypto from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import express from 'express';

loadDotEnv();

const app = express();
const port = Number(process.env.PORT ?? 4021);
const authServerUrl = (process.env.AUTH_SERVER_URL ?? 'https://mfa.node-hub.com').replace(/\/$/, '');
const authAppToken = process.env.AUTH_APP_TOKEN;
const defaultUserHint = process.env.AUTH_USER_HINT ?? 'demo@example.local';
const sessionSecret = process.env.SESSION_SECRET ?? authAppToken;

app.use(express.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  res.send(page(`
    <h1>Express basic</h1>
    <p><a href="/protected">Open protected page</a></p>
  `));
});

app.get('/protected', async (req, res, next) => {
  try {
    const session = readSession(req);
    if (session?.mfa === true) {
      res.send(page(`
        <h1>Protected page</h1>
        <p>Access granted for <code>${escapeHtml(session.userHint)}</code>.</p>
        <p><a href="/logout">Logout</a></p>
      `));
      return;
    }

    const challengeId = req.query.challenge?.toString();
    const userHint = req.query.user?.toString() ?? defaultUserHint;

    if (challengeId) {
      const challenge = await getChallenge(challengeId);

      if (challenge.status === 'approved') {
        res.setHeader('set-cookie', createSession({ mfa: true, userHint }));
        res.redirect('/protected');
        return;
      }

      if (challenge.status === 'denied' || challenge.status === 'expired') {
        res.send(page(`<h1>Access refused</h1><p>Status: <code>${escapeHtml(challenge.status)}</code></p><p><a href="/protected">Retry</a></p>`));
        return;
      }

      res.send(page(`
        <h1>MFA required</h1>
        ${challenge.numberMatch ? `<p>Confirm this number: <strong>${escapeHtml(challenge.numberMatch)}</strong></p>` : ''}
        <p>Status: <code>${escapeHtml(challenge.status)}</code></p>
        <script>setTimeout(() => location.reload(), 2000)</script>
      `));
      return;
    }

    res.send(page(`
      <h1>Protected page</h1>
      <form method="post" action="/protected/start">
        <label>Email <input name="userHint" type="email" value="${escapeHtml(defaultUserHint)}" required></label>
        <button type="submit">Request access</button>
      </form>
    `));
  } catch (error) {
    next(error);
  }
});

app.post('/protected/start', async (req, res, next) => {
  try {
    const userHint = String(req.body.userHint ?? '').trim().toLowerCase();
    const challenge = await createChallenge(userHint, 'Express basic /protected');
    res.redirect(`/protected?challenge=${encodeURIComponent(challenge.id)}&user=${encodeURIComponent(userHint)}`);
  } catch (error) {
    next(error);
  }
});

app.get('/logout', (_req, res) => {
  res.setHeader('set-cookie', 'example_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.redirect('/');
});

app.listen(port, () => {
  console.log(`Express basic listening on http://localhost:${port}`);
});

async function createChallenge(userHint, resource) {
  if (!authAppToken) {
    throw new Error('AUTH_APP_TOKEN is required.');
  }

  const response = await fetch(`${authServerUrl}/api/challenges`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${authAppToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ userHint, resource, mode: 'push_with_number', location: 'Express basic' }),
  });

  if (!response.ok) {
    throw new Error(`Challenge creation failed: ${response.status} ${await response.text()}`);
  }

  return (await response.json()).challenge;
}

async function getChallenge(challengeId) {
  const response = await fetch(`${authServerUrl}/api/challenges/${encodeURIComponent(challengeId)}`);
  if (!response.ok) {
    throw new Error(`Challenge read failed: ${response.status} ${await response.text()}`);
  }

  return (await response.json()).challenge;
}

function createSession(session) {
  const payload = Buffer.from(JSON.stringify({ ...session, expiresAt: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', sessionSecret ?? 'change-me').update(payload).digest('base64url');
  return `example_session=${encodeURIComponent(`${payload}.${signature}`)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`;
}

function readSession(req) {
  const raw = req.headers.cookie?.split(';').map((part) => part.trim()).find((part) => part.startsWith('example_session='))?.slice('example_session='.length);
  if (!raw) return undefined;

  const [payload, signature] = decodeURIComponent(raw).split('.');
  if (!payload || !signature) return undefined;

  const expected = crypto.createHmac('sha256', sessionSecret ?? 'change-me').update(payload).digest('base64url');
  if (Buffer.byteLength(signature) !== Buffer.byteLength(expected)) return undefined;

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return undefined;

  const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  return session.expiresAt > Date.now() ? session : undefined;
}

function page(body) {
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Express basic</title><body>${body}</body></html>`;
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
