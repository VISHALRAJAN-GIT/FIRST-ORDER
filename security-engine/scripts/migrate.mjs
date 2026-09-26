#!/usr/bin/env node
/**
 * Apply raw SQL migrations in `migrations/` in filename order.
 *
 * Deliberately not an ORM migration tool. The security engine owns five tables
 * with triggers, partial indexes and CHECK constraints whose exact SQL is part of
 * the security argument — an ORM that "helpfully" rewrites DDL would be able to
 * silently drop the append-only trigger that makes `audit_logs` trustworthy.
 *
 * Each file runs in its own transaction and is recorded in
 * `sec_schema_migrations`, so re-running is safe.
 *
 *   npm run migrate
 *   DATABASE_URL=postgres://... npm run migrate
 */

import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = resolve(here, '..', 'migrations');

const databaseUrl =
  process.env.DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5432/tixify';

let pg;
try {
  pg = (await import('pg')).default;
} catch {
  process.stderr.write('ERROR: the `pg` package is not installed. Run: npm install\n');
  process.exit(1);
}

const client = new pg.Client({ connectionString: databaseUrl });

try {
  await client.connect();
} catch (error) {
  process.stderr.write(`ERROR: cannot connect to Postgres at ${redact(databaseUrl)}\n`);
  process.stderr.write(`       ${error.message}\n`);
  process.stderr.write('       Start the test infrastructure first:  npm run infra:up\n');
  process.exit(1);
}

function redact(url) {
  return url.replace(/\/\/([^:]+):([^@]+)@/, '//$1:***@');
}

try {
  await client.query(`
    CREATE TABLE IF NOT EXISTS sec_schema_migrations (
      version    TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  const files = (await readdir(migrationsDir)).filter((name) => name.endsWith('.sql')).sort();

  if (files.length === 0) {
    process.stdout.write('No migrations found.\n');
  }

  let applied = 0;
  for (const file of files) {
    const version = file.replace(/\.sql$/, '');
    const { rows } = await client.query(
      'SELECT 1 FROM sec_schema_migrations WHERE version = $1',
      [version],
    );
    if (rows.length > 0) {
      process.stdout.write(`= ${version} (already applied)\n`);
      continue;
    }

    const sql = await readFile(join(migrationsDir, file), 'utf8');
    // The migration files manage their own BEGIN/COMMIT so that a partially
    // applied file cannot be recorded as applied.
    await client.query(sql);
    await client.query('INSERT INTO sec_schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING', [
      version,
    ]);
    applied += 1;
    process.stdout.write(`+ ${version}\n`);
  }

  process.stdout.write(
    applied === 0 ? 'Schema already up to date.\n' : `Applied ${applied} migration(s).\n`,
  );
} catch (error) {
  process.stderr.write(`ERROR: migration failed: ${error.message}\n`);
  process.exitCode = 1;
} finally {
  await client.end();
}
