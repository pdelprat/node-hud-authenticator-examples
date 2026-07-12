import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

loadDotEnv();

const authServerUrl = (process.env.AUTH_SERVER_URL ?? 'https://mfa.node-hub.com').replace(/\/$/, '');
const authAppToken = process.env.AUTH_APP_TOKEN;
const userHint = process.argv[2] ?? process.env.AUTH_USER_HINT ?? 'demo@example.local';
const resource = process.env.AUTH_RESOURCE ?? 'JS simple protected action';
const location = process.env.AUTH_LOCATION ?? 'Local script';

if (!authAppToken) {
  throw new Error('AUTH_APP_TOKEN is required.');
}

const challenge = await createChallenge();
console.log(`Challenge ${challenge.id} created for ${userHint}`);
console.log(`Status: ${challenge.status}`);

if (challenge.numberMatch) {
  console.log(`Confirm this number in Node-hud Authenticator: ${challenge.numberMatch}`);
}

const approved = await waitForDecision(challenge.id);
console.log(approved ? 'Access granted.' : 'Access refused.');
process.exit(approved ? 0 : 1);

async function createChallenge() {
  const response = await fetch(`${authServerUrl}/api/challenges`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${authAppToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      userHint,
      resource,
      mode: 'push_with_number',
      location,
    }),
  });

  if (!response.ok) {
    throw new Error(`Challenge creation failed: ${response.status} ${await response.text()}`);
  }

  const body = await response.json();
  return body.challenge;
}

async function waitForDecision(challengeId) {
  for (;;) {
    await sleep(2000);

    const response = await fetch(`${authServerUrl}/api/challenges/${encodeURIComponent(challengeId)}`);
    if (!response.ok) {
      throw new Error(`Challenge read failed: ${response.status} ${await response.text()}`);
    }

    const body = await response.json();
    const challenge = body.challenge;
    console.log(`Status: ${challenge.status}`);

    if (challenge.status === 'approved') {
      return true;
    }

    if (challenge.status === 'denied' || challenge.status === 'expired') {
      return false;
    }
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function loadDotEnv(path = resolve(process.cwd(), '.env')) {
  if (!existsSync(path)) {
    return;
  }

  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const separator = trimmed.indexOf('=');
    if (separator === -1) {
      continue;
    }

    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim().replace(/^['"]|['"]$/g, '');
    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}
