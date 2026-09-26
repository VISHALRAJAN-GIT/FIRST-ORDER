#!/bin/sh
# Creates the booking app database next to the security engine's own database.
#
# Postgres only runs scripts under docker-entrypoint-initdb.d on first
# initialisation of an empty volume, so this is a convenience for a fresh
# `pnpm run infra:up`. The databases it creates are also created idempotently
# by scripts/dev-db.mjs, which is what the app and engine actually call, so a
# re-created volume is never a problem.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<-EOSQL
    SELECT 'CREATE DATABASE tixify_app'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'tixify_app')\gexec
EOSQL
