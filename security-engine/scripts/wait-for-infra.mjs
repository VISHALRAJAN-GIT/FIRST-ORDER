#!/usr/bin/env node
/**
 * Block until the test Redis and Postgres are accepting connections.
 *
 * Exists because `docker compose up -d` returns as soon as containers are
 * *created*, not when they are *ready*. Without this, the first test run after a
 * cold start fails with a connection error that looks like a product bug.
 *
 *   npm run infra:wait
 */

import net from 'node:net';

const TARGETS = [
  { name: 'redis', host: '127.0.0.1', port: 6379, timeoutMs: 60_000 },
  { name: 'postgres', host: '127.0.0.1', port: 5432, timeoutMs: 60_000 },
];

function probe({ host, port }, timeoutMs = 1_000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const done = (ok) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}

async function waitFor(target) {
  const deadline = Date.now() + target.timeoutMs;
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt += 1;
    if (await probe(target)) {
      process.stdout.write(`  ${target.name} ready (attempt ${attempt})\n`);
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  return false;
}

const results = await Promise.all(TARGETS.map(waitFor));
const failed = TARGETS.filter((_, index) => !results[index]);

if (failed.length > 0) {
  process.stderr.write(
    `\nTimed out waiting for: ${failed.map((target) => target.name).join(', ')}\n` +
      'Start the test infrastructure first:  npm run infra:up\n',
  );
  process.exit(1);
}

process.stdout.write('Test infrastructure is ready.\n');
