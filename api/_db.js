// Database driver abstraction for Codecanic.
//
// Production: managed Postgres via node-postgres (`pg`) when DATABASE_URL is set.
// Local/dev/test: embedded Postgres via PGlite (real Postgres in WASM, no server)
// persisted under ${CODECANIC_DATA_DIR}/pgdata, so the SAME SQL runs everywhere.
//
// Exposes q(sql, params) -> rows and withTx(fn) -> runs fn in a transaction with
// its own bound q. Schema is created lazily on first use (idempotent).
import { join } from "node:path";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  email text UNIQUE NOT NULL,
  name text,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  terms_accepted_at timestamptz,
  privacy_accepted_at timestamptz,
  marketing_opt_in boolean NOT NULL DEFAULT false,
  age_confirmed boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS organizations (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  slug text UNIQUE NOT NULL,
  plan text NOT NULL DEFAULT 'Free',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS memberships (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'member',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, organization_id)
);
CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS connector_creds (
  id uuid PRIMARY KEY,
  provider text NOT NULL,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  access_token text NOT NULL,
  refresh_token text,
  token_type text,
  scope text,
  expires_in integer,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, organization_id)
);
CREATE TABLE IF NOT EXISTS reports (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  source_url text,
  created_at timestamptz NOT NULL DEFAULT now(),
  summary jsonb,
  findings jsonb
);
CREATE TABLE IF NOT EXISTS login_attempts (
  key text PRIMARY KEY,
  count integer NOT NULL DEFAULT 0,
  lock_until timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS auth_tokens (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_org ON memberships(organization_id);
CREATE INDEX IF NOT EXISTS idx_reports_org ON reports(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_creds_org ON connector_creds(organization_id);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens(user_id, kind);

-- Additive migrations (idempotent) for existing deployments.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;
`;

let backend = null; // { kind, q, withTx, close, truncate }
let readyPromise = null;

async function buildPgBackend(connectionString) {
  const pg = (await import("pg")).default;
  const ssl = /sslmode=disable|localhost|127\.0\.0\.1/.test(connectionString) ? false : { rejectUnauthorized: false };
  const pool = new pg.Pool({ connectionString, ssl, max: Number(process.env.CODECANIC_PG_POOL || 10) });
  return {
    kind: "postgres",
    async exec(sql) { await pool.query(sql); },
    async q(text, params) { return (await pool.query(text, params)).rows; },
    async withTx(fn) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await fn((t, p) => client.query(t, p).then((r) => r.rows));
        await client.query("COMMIT");
        return result;
      } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
    async close() { await pool.end(); },
    async truncate() {
      await pool.query("TRUNCATE users, organizations, memberships, sessions, connector_creds, reports CASCADE");
    }
  };
}

async function buildPgliteBackend() {
  const { PGlite } = await import("@electric-sql/pglite");
  const inMemory = process.env.CODECANIC_PGLITE_MEMORY === "1";
  const dataDir = inMemory ? undefined : join(process.env.CODECANIC_DATA_DIR || ".data", "pgdata");
  const db = new PGlite(dataDir);
  await db.waitReady;
  return {
    kind: "pglite",
    async exec(sql) { await db.exec(sql); },
    async q(text, params) { return (await db.query(text, params)).rows; },
    async withTx(fn) {
      return db.transaction(async (tx) => fn((t, p) => tx.query(t, p).then((r) => r.rows)));
    },
    async close() { await db.close(); },
    async truncate() {
      await db.query("TRUNCATE users, organizations, memberships, sessions, connector_creds, reports CASCADE");
    }
  };
}

async function init() {
  const url = process.env.DATABASE_URL;
  backend = url ? await buildPgBackend(url) : await buildPgliteBackend();
  await backend.exec(SCHEMA);
  return backend;
}

function ready() {
  if (!readyPromise) readyPromise = init();
  return readyPromise;
}

export async function q(text, params = []) {
  const b = await ready();
  return b.q(text, params);
}

export async function withTx(fn) {
  const b = await ready();
  return b.withTx(fn);
}

export async function backendKind() {
  return (await ready()).kind;
}

// Test/maintenance helpers.
export async function resetDb() {
  const b = await ready();
  await b.truncate();
}

export async function closeDb() {
  if (!readyPromise) return;
  const b = await readyPromise;
  await b.close();
  backend = null;
  readyPromise = null;
}
