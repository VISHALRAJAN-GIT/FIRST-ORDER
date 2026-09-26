#!/usr/bin/env node
/**
 * Generate an Ed25519 ticket signing key pair.
 *
 * Emits environment-variable lines ready to paste into `.env`, a secret manager,
 * or a Vercel environment. Keys are printed to stdout exactly once and are never
 * written to disk by this script — the operator decides where they live.
 *
 * Usage:
 *   npm run keys:generate
 *   npm run keys:generate -- --kid key-2
 *   npm run keys:generate -- --retire-in-days 7
 *
 * The private key is base64 of the raw 32-byte seed rather than PEM, because
 * most secret-management UIs and .env editors mangle PEM armour (line wrapping,
 * quote handling, trailing-newline stripping) while passing base64 through
 * intact.
 */

import { generateKeyPairSync } from 'node:crypto';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_RAW_BYTES = 32;

function parseArgs(argv) {
  const options = { kid: 'key-1', retireInDays: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--kid' && argv[i + 1]) {
      options.kid = argv[i + 1];
      i += 1;
    } else if (arg === '--retire-in-days' && argv[i + 1]) {
      options.retireInDays = Number.parseInt(argv[i + 1], 10);
      i += 1;
      if (!Number.isFinite(options.retireInDays) || options.retireInDays < 1) {
        fail('--retire-in-days must be a positive integer');
      }
    } else if (arg === '--help' || arg === '-h') {
      process.stdout.write(
        'Usage: npm run keys:generate -- [--kid <id>] [--retire-in-days <n>]\n',
      );
      process.exit(0);
    } else {
      fail(`Unknown argument: ${arg}`);
    }
  }
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(options.kid)) {
    fail('--kid must be 1-64 characters of [A-Za-z0-9_-]');
  }
  return options;
}

function fail(message) {
  process.stderr.write(`ERROR: ${message}\n`);
  process.exit(1);
}

const { kid, retireInDays } = parseArgs(process.argv.slice(2));

const { privateKey, publicKey } = generateKeyPairSync('ed25519');

const privateKeyBase64 = privateKey
  .export({ format: 'der', type: 'pkcs8' })
  .subarray(PKCS8_PREFIX.length)
  .toString('base64');
const publicKeyBase64 = publicKey
  .export({ format: 'der', type: 'spki' })
  .subarray(SPKI_PREFIX.length)
  .toString('base64');

if (Buffer.from(privateKeyBase64, 'base64').length !== ED25519_RAW_BYTES) {
  fail('Generated private key has an unexpected length; refusing to emit.');
}

const retireAt =
  retireInDays === null
    ? '2030-01-01T00:00:00.000Z'
    : new Date(Date.now() + retireInDays * 86_400_000).toISOString();

const lines = [
  '',
  '# ---------------------------------------------------------------',
  `# Ed25519 ticket signing key pair  (kid: ${kid})`,
  '# ---------------------------------------------------------------',
  '# TICKET_SIGNING_PRIVATE_KEY is SERVER ONLY.',
  '# It must never be committed, bundled into frontend code, or placed in a QR.',
  '',
  `TICKET_SIGNING_PRIVATE_KEY=${privateKeyBase64}`,
  `TICKET_SIGNING_PUBLIC_KEY=${publicKeyBase64}`,
  `TICKET_SIGNING_KEY_ID=${kid}`,
  `TICKET_SIGNING_TRUSTED_KEY_IDS=${kid}`,
  `# Must be at least TICKET_TTL_SECONDS into the future, or live tickets break.`,
  `TICKET_SIGNING_RETIRE_AT=${retireAt}`,
  '',
];

process.stdout.write(lines.join('\n'));

if (process.env.NODE_ENV === 'production') {
  process.stderr.write(
    '\nWARNING: keys were printed to stdout in a production shell. Ensure this output is not captured in CI logs.\n',
  );
}
