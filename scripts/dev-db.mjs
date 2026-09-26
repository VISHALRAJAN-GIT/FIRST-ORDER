#!/usr/bin/env node
/**
 * Bring a local development database up to the state the app expects.
 *
 * The workspace needs two PostgreSQL databases, because the booking app and the
 * security engine own disjoint tables and must not share a schema:
 *
 *   tixify_app   users, venues, events, inventory, bookings, tickets, ...
 *   tixify       the engine's telemetry, audit, idempotency and scan tables
 *
 * Postgres will not create a database from inside a transaction and has no
 * `CREATE DATABASE IF NOT EXISTS`, so this connects to the maintenance
 * `postgres` database, checks `pg_database`, and creates what is missing. It is
 * idempotent: running it against an already-provisioned volume is a no-op.
 *
 *   node scripts/dev-db.mjs            ensure both databases exist
 *   node scripts/dev-db.mjs --drop     drop and recreate the app database
 *
 * `infra:up` mounts scripts/docker/init-databases.sh into the Postgres image,
 * which does the same thing on first boot. This script exists because that hook
 * only fires on an empty volume, and because the app database also needs the
 * drizzle schema applied to it, which is the second half of this script.
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

const ADMIN_URL =
  process.env.ADMIN_DATABASE_URL ??
  process.env.DATABASE_ADMIN_URL ??
  'postgres://postgres:postgres@127.0.0.1:5432/postgres';
const APP_DATABASE = process.env.APP_DATABASE_NAME ?? 'tixify_app';
const ENGINE_DATABASE = process.env.ENGINE_DATABASE_NAME ?? 'tixify';
const dropAppDatabase = process.argv.includes('--drop');

let pg;
try {
  pg = (await import('pg')).default;
} catch {
  process.stderr.write('ERROR: the `pg` package is not installed. Run: pnpm install\n');
  process.exit(1);
}

const client = new pg.Client({ connectionString: ADMIN_URL });

async function main() {
  try {
    await client.connect();
  } catch (error) {
    process.stderr.write(`ERROR: cannot connect to Postgres at ${redact(ADMIN_URL)}\n`);
    process.stderr.write(`       ${error.message}\n`);
    process.stderr.write('       Start it first:  pnpm run infra:up\n');
    process.exit(1);
  }

  if (dropAppDatabase) {
    process.stdout.write(`- dropping ${APP_DATABASE}\n`);
    // Terminate stragglers first; a leftover pool would make DROP fail.
    await client.query(
      `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
       WHERE datname = $1 AND pid <> pg_backend_pid()`,
      [APP_DATABASE],
    );
    await client.query(`DROP DATABASE IF EXISTS "${APP_DATABASE}"`);
  }

  for (const name of [ENGINE_DATABASE, APP_DATABASE]) {
    const { rows } = await client.query('SELECT 1 FROM pg_database WHERE datname = $1', [name]);
    if (rows.length > 0) {
      process.stdout.write(`= ${name} (exists)\n`);
      continue;
    }
    // CREATE DATABASE cannot be parameterised, and the name comes from our own
    // environment rather than user input, but quote it regardless so a name
    // with a dash or quote cannot break out of the identifier.
    await client.query(`CREATE DATABASE "${name.replace(/"/g, '""')}"`);
    process.stdout.write(`+ ${name}\n`);
  }

  await client.end();
  applyAppSchema();
}

function applyAppSchema() {
  const appUrl = databaseUrlFor(APP_DATABASE);
  process.stdout.write(`\nApplying the booking app drizzle schema to ${APP_DATABASE}...\n`);
  const result = spawnSync(process.execPath, [drizzleKitEntry(), 'migrate'], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: { ...process.env, DATABASE_URL: appUrl },
  });
  if (result.status !== 0) {
    process.stderr.write('ERROR: drizzle-kit migrate failed.\n');
    process.exit(result.status ?? 1);
  }

  process.stdout.write('\nApplying the security engine schema...\n');
  const engine = spawnSync(process.execPath, ['packages/security-engine/scripts/migrate.mjs'], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: { ...process.env, DATABASE_URL: databaseUrlFor(ENGINE_DATABASE) },
  });
  if (engine.status !== 0) {
    process.stderr.write('ERROR: the security engine migration failed.\n');
    process.exit(engine.status ?? 1);
  }

  process.stdout.write('\nDatabases are ready.\n');
  process.stdout.write(`  app     DATABASE_URL=${appUrl}\n`);
  process.stdout.write(`  engine  DATABASE_URL=${databaseUrlFor(ENGINE_DATABASE)}\n`);
}

/**
 * Resolve drizzle-kit's JavaScript entry point and run it with the current Node
 * binary.
 *
 * Going through `npx --shell true` would concatenate the arguments into a
 * command line, which newer Node warns about precisely because it is an
 * injection vector once an argument can carry a database name. Invoking the
 * entry point directly keeps this shell-free on every platform. On Windows the
 * `node_modules/.bin/drizzle-kit.cmd` shim cannot be spawned without a shell
 * at all, which is the failure this avoids.
 */
function drizzleKitEntry() {
  const entry = resolve(repoRoot, 'node_modules', 'drizzle-kit', 'bin.cjs');
  if (!existsSync(entry)) {
    process.stderr.write('ERROR: drizzle-kit is not installed. Run: pnpm install\n');
    process.exit(1);
  }
  return entry;
}

function databaseUrlFor(name) {
  const url = new URL(ADMIN_URL);
  url.pathname = `/${name}`;
  return url.toString();
}

function redact(url) {
  return url.replace(/\/\/([^:]+):([^@]+)@/, '//$1:***@');
}

main().catch((error) => {
  process.stderr.write(`ERROR: ${error.message}\n`);
  process.exit(1);
});
