// Database driver abstraction for Codecanic.
//
// Production: managed Postgres via node-postgres (`pg`) when DATABASE_URL is set.
// Local/dev/test: embedded Postgres via PGlite (real Postgres in WASM, no server)
// persisted under ${CODECANIC_DATA_DIR}/pgdata, so the SAME SQL runs everywhere.
//
// Exposes q(sql, params) -> rows and withTx(fn) -> runs fn in a transaction with
// its own bound q. Schema is created lazily on first use (idempotent).
import { join } from "node:path";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";

export const SCHEMA = `
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
CREATE TABLE IF NOT EXISTS jobs (
  id uuid PRIMARY KEY,
  type text NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  payload jsonb NOT NULL,
  result jsonb,
  error text,
  attempts integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz
);
CREATE TABLE IF NOT EXISTS suppressions (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  fingerprint text NOT NULL,
  reason text,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS github_installations (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  installation_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS stripe_events (
  id text PRIMARY KEY,
  processed_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS org_rate_limits (
  key text PRIMARY KEY,
  window_start timestamptz NOT NULL DEFAULT now(),
  count integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_jobs_queued ON jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_org ON jobs(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_suppressions_org ON suppressions(organization_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_org ON memberships(organization_id);
CREATE INDEX IF NOT EXISTS idx_reports_org ON reports(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_creds_org ON connector_creds(organization_id);
CREATE INDEX IF NOT EXISTS idx_auth_tokens_user ON auth_tokens(user_id, kind);

-- Additive migrations (idempotent) for existing deployments.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false;
-- R2: per-job heartbeat so the requeue sweep only resurrects jobs whose worker
-- has actually gone quiet (not legitimately-long-running scans).
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS heartbeat_at timestamptz;
-- R8: decouple "how many times claimed" from the retry/error budget so a
-- stale-requeued-but-fine job doesn't burn an attempt.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS claim_count integer NOT NULL DEFAULT 0;
-- S2: stash the Stripe customer id at checkout so a subscription.deleted webhook
-- (which doesn't echo session metadata) can still resolve the org to downgrade.
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS stripe_customer_id text;
CREATE INDEX IF NOT EXISTS idx_orgs_stripe_customer ON organizations(stripe_customer_id);
`;

let backend = null; // { kind, q, withTx, close, truncate }
let readyPromise = null;

async function buildPgBackend(connectionString) {
  const pg = (await import("pg")).default;
  // No TLS on local or Railway private-network connections (railway.internal);
  // TLS for everything else (managed public endpoints). Certificate verification
  // is ON by default (managed PG providers present CA-signed certs); set
  // CODECANIC_PG_INSECURE_SSL=1 only if a provider truly requires relaxed certs.
  const noSsl = /sslmode=disable|localhost|127\.0\.0\.1|\.railway\.internal/.test(connectionString);
  const insecure = process.env.CODECANIC_PG_INSECURE_SSL === "1";
  const ssl = noSsl ? false : { rejectUnauthorized: !insecure };
  const pool = new pg.Pool({
    connectionString,
    ssl,
    max: Number(process.env.CODECANIC_PG_POOL || 10),
    connectionTimeoutMillis: Number(process.env.CODECANIC_PG_CONNECT_TIMEOUT_MS || 8000),
    idleTimeoutMillis: Number(process.env.CODECANIC_PG_IDLE_TIMEOUT_MS || 30000),
    statement_timeout: Number(process.env.CODECANIC_PG_STATEMENT_TIMEOUT_MS || 30000)
  });
  // A pool 'error' on an idle client would otherwise crash the process.
  pool.on("error", (err) => {
    process.stderr.write(JSON.stringify({ level: "error", msg: "pg.pool_error", err: String(err?.message || err) }) + "\n");
  });
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

// Mirrors _auth.isProductionLike() — kept local to avoid an import cycle
// (_auth -> _repo -> _db).
function isProductionLike() {
  return Boolean(
    process.env.NODE_ENV === "production" ||
      process.env.VERCEL === "1" ||
      process.env.RAILWAY_ENVIRONMENT ||
      process.env.RAILWAY_PROJECT_ID
  );
}

async function init() {
  const url = process.env.DATABASE_URL;
  // Refuse to boot in production on the embedded PGlite store: it lives on the
  // container's ephemeral disk, so every redeploy/restart would silently wipe
  // all users, orgs, reports, and jobs. Require a managed Postgres URL instead.
  if (!url && isProductionLike() && process.env.CODECANIC_ALLOW_EPHEMERAL_DB !== "1") {
    throw new Error(
      "DATABASE_URL must be set in production. Refusing to start on ephemeral PGlite (data would be lost on redeploy). " +
        "Set CODECANIC_ALLOW_EPHEMERAL_DB=1 to override for a throwaway environment."
    );
  }
  backend = url ? await buildPgBackend(url) : await buildPgliteBackend();
  await backend.exec(SCHEMA);
  // When moving to managed Postgres, copy the volume's PGlite (current source of
  // truth) first; fall back to the legacy JSON file only if still empty.
  if (url) await migratePgliteToPostgres(backend);
  await migrateLegacyJson(backend);
  return backend;
}

const COPY_TABLES = ["users", "organizations", "memberships", "sessions", "connector_creds", "reports", "auth_tokens", "login_attempts", "jobs", "suppressions", "github_installations"];
const JSONB_COLS = { reports: ["summary", "findings"], jobs: ["payload", "result"] };

// Copy every table from a source query fn to a destination query fn. Idempotent
// (ON CONFLICT DO NOTHING). Exported for tests; used by the PGlite→Postgres move.
export async function copyAllTables(srcQuery, dstQuery) {
  const counts = {};
  for (const table of COPY_TABLES) {
    let rows;
    try {
      rows = await srcQuery(`SELECT * FROM ${table}`);
    } catch {
      continue; // table absent in the source — skip
    }
    const jsonb = new Set(JSONB_COLS[table] || []);
    for (const row of rows) {
      const cols = Object.keys(row);
      const placeholders = cols.map((c, i) => (jsonb.has(c) ? `$${i + 1}::jsonb` : `$${i + 1}`)).join(",");
      const vals = cols.map((c) => {
        const v = row[c];
        if (v instanceof Date) return v.toISOString();
        if (jsonb.has(c)) return v == null ? null : JSON.stringify(v);
        return v;
      });
      await dstQuery(`INSERT INTO ${table} (${cols.join(",")}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`, vals);
    }
    counts[table] = rows.length;
  }
  return counts;
}

// One-time, idempotent, NON-destructive copy of the volume's embedded PGlite
// database into managed Postgres. Runs only when Postgres is empty and a local
// PGlite database exists. The PGlite files are left in place, so unsetting
// DATABASE_URL cleanly reverts to the previous data.
async function migratePgliteToPostgres(pgBackend) {
  try {
    const n = (await pgBackend.q("SELECT count(*)::int AS n FROM users"))[0]?.n ?? 0;
    if (n > 0) return;
    const pglitePath = join(process.env.CODECANIC_DATA_DIR || ".data", "pgdata");
    if (!existsSync(pglitePath)) return;
    const { PGlite } = await import("@electric-sql/pglite");
    const src = new PGlite(pglitePath);
    await src.waitReady;
    try {
      const counts = await copyAllTables(
        async (sql, params) => (await src.query(sql, params)).rows,
        (sql, params) => pgBackend.q(sql, params)
      );
      process.stdout.write(JSON.stringify({ level: "info", msg: "migrate.pglite_to_pg", ...counts }) + "\n");
    } finally {
      await src.close();
    }
  } catch (err) {
    process.stderr.write(JSON.stringify({ level: "error", msg: "migrate.pglite_to_pg_failed", err: String(err?.message || err) }) + "\n");
  }
}

// One-time, idempotent import of the pre-Postgres JSON-file store. Runs only
// when the relational tables are empty AND a legacy ${DATA_DIR}/codecanic.json
// exists, so deploying the relational version doesn't orphan existing accounts.
async function migrateLegacyJson(b) {
  try {
    const userCount = (await b.q("SELECT count(*)::int AS n FROM users"))[0]?.n ?? 0;
    if (userCount > 0) return;
    const legacyPath = join(process.env.CODECANIC_DATA_DIR || ".data", "codecanic.json");
    let data;
    try {
      data = JSON.parse(await readFile(legacyPath, "utf8"));
    } catch {
      return; // no legacy file → nothing to migrate
    }
    const counts = await b.withTx(async (q) => {
      for (const u of data.users || []) {
        await q(
          `INSERT INTO users (id,email,name,password_hash,created_at,terms_accepted_at,privacy_accepted_at,marketing_opt_in,age_confirmed,email_verified)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true) ON CONFLICT (id) DO NOTHING`,
          [u.id, u.email, u.name, u.passwordHash, u.createdAt || new Date().toISOString(),
           u.termsAcceptedAt || null, u.privacyAcceptedAt || null, u.marketingOptIn === true, u.ageConfirmed === true]
        );
      }
      for (const o of data.organizations || []) {
        await q(`INSERT INTO organizations (id,name,slug,plan,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING`,
          [o.id, o.name, o.slug, o.plan || "Free", o.createdAt || new Date().toISOString()]);
      }
      for (const m of data.memberships || []) {
        await q(`INSERT INTO memberships (id,user_id,organization_id,role,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING`,
          [m.id, m.userId, m.organizationId, m.role || "member", m.createdAt || new Date().toISOString()]);
      }
      for (const s of data.sessions || []) {
        await q(`INSERT INTO sessions (id,user_id,created_at,expires_at) VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING`,
          [s.id, s.userId, s.createdAt || new Date().toISOString(), s.expiresAt]);
      }
      for (const c of data.connectorCreds || []) {
        await q(
          `INSERT INTO connector_creds (id,provider,organization_id,user_id,access_token,refresh_token,token_type,scope,expires_in,updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (provider, organization_id) DO NOTHING`,
          [c.id, c.provider, c.organizationId, c.userId || null, c.accessToken, c.refreshToken || null,
           c.tokenType || null, c.scope || null, c.expiresIn || null, c.updatedAt || new Date().toISOString()]
        );
      }
      for (const r of data.reports || []) {
        await q(
          `INSERT INTO reports (id,organization_id,source_url,created_at,summary,findings) VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb) ON CONFLICT (id) DO NOTHING`,
          [r.id, r.organizationId, r.sourceUrl || null, r.createdAt || new Date().toISOString(),
           JSON.stringify(r.summary ?? null), JSON.stringify(r.findings ?? [])]
        );
      }
      return { users: (data.users || []).length, organizations: (data.organizations || []).length };
    });
    process.stdout.write(JSON.stringify({ level: "info", msg: "migrate.legacy_json", ...counts }) + "\n");
  } catch (err) {
    process.stderr.write(JSON.stringify({ level: "error", msg: "migrate.legacy_json_failed", err: String(err?.message || err) }) + "\n");
  }
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
