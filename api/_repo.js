// Typed relational data access for Codecanic (replaces the JSON-file store).
// All SQL lives here; handlers call these functions. Rows are mapped to the
// camelCase shapes the rest of the app already expects.
import { randomUUID } from "node:crypto";
import { q, withTx } from "./_db.js";

const iso = (v) => (v instanceof Date ? v.toISOString() : v);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (v) => typeof v === "string" && UUID_RE.test(v);

const mapUser = (r) => r && {
  id: r.id, email: r.email, name: r.name, passwordHash: r.password_hash,
  createdAt: iso(r.created_at), termsAcceptedAt: iso(r.terms_accepted_at),
  privacyAcceptedAt: iso(r.privacy_accepted_at), marketingOptIn: r.marketing_opt_in,
  ageConfirmed: r.age_confirmed, emailVerified: r.email_verified
};
const mapOrg = (r) => r && { id: r.id, name: r.name, slug: r.slug, plan: r.plan, createdAt: iso(r.created_at) };
const mapMembership = (r) => r && { id: r.id, userId: r.user_id, organizationId: r.organization_id, role: r.role, createdAt: iso(r.created_at) };
const mapSession = (r) => r && { id: r.id, userId: r.user_id, createdAt: iso(r.created_at), expiresAt: iso(r.expires_at) };
const mapCred = (r) => r && {
  id: r.id, provider: r.provider, organizationId: r.organization_id, userId: r.user_id,
  accessToken: r.access_token, refreshToken: r.refresh_token, tokenType: r.token_type,
  scope: r.scope, expiresIn: r.expires_in, updatedAt: iso(r.updated_at)
};
const mapReport = (r) => r && {
  id: r.id, organizationId: r.organization_id, sourceUrl: r.source_url,
  createdAt: iso(r.created_at), summary: r.summary, findings: r.findings
};

async function uniqueSlug(query, base) {
  let slug = base || "org";
  let suffix = 1;
  // eslint-disable-next-line no-await-in-loop
  while ((await query("SELECT 1 FROM organizations WHERE slug=$1", [slug])).length) {
    suffix += 1;
    slug = `${base}-${suffix}`;
  }
  return slug;
}

// --- users ----------------------------------------------------------------
export async function findUserByEmail(email) {
  const rows = await q("SELECT * FROM users WHERE email=$1", [email]);
  return mapUser(rows[0]);
}

export async function findUserById(id) {
  if (!isUuid(id)) return null;
  const rows = await q("SELECT * FROM users WHERE id=$1", [id]);
  return mapUser(rows[0]);
}

export async function updateUserPassword(userId, passwordHash) {
  await q("UPDATE users SET password_hash=$2 WHERE id=$1", [userId, passwordHash]);
}

export async function markEmailVerified(userId) {
  await q("UPDATE users SET email_verified=true WHERE id=$1", [userId]);
}

// Creates the user, a personal organization (unique slug), and an owner
// membership atomically. `user` carries the already-hashed password.
export async function createUserWithOrg(user, orgBaseSlug, orgName) {
  return withTx(async (query) => {
    await query(
      `INSERT INTO users (id,email,name,password_hash,created_at,terms_accepted_at,privacy_accepted_at,marketing_opt_in,age_confirmed,email_verified)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [user.id, user.email, user.name, user.passwordHash, user.createdAt, user.termsAcceptedAt,
       user.privacyAcceptedAt, user.marketingOptIn, user.ageConfirmed, user.emailVerified === true]
    );
    const slug = await uniqueSlug(query, orgBaseSlug);
    const org = { id: randomUUID(), name: orgName, slug, plan: "Free", createdAt: user.createdAt };
    await query("INSERT INTO organizations (id,name,slug,plan,created_at) VALUES ($1,$2,$3,$4,$5)",
      [org.id, org.name, org.slug, org.plan, org.createdAt]);
    const membership = { id: randomUUID(), userId: user.id, organizationId: org.id, role: "owner", createdAt: user.createdAt };
    await query("INSERT INTO memberships (id,user_id,organization_id,role,created_at) VALUES ($1,$2,$3,$4,$5)",
      [membership.id, membership.userId, membership.organizationId, membership.role, membership.createdAt]);
    return { user, organization: org, membership };
  });
}

// Deletes the user, plus any organization they solely own (cascades clean up
// memberships, connector creds, and reports), in one transaction.
export async function deleteUserAndSoleOwnedOrgs(userId) {
  return withTx(async (query) => {
    await query(
      `DELETE FROM organizations o
       USING memberships m
       WHERE m.user_id=$1 AND m.role='owner' AND m.organization_id=o.id
         AND (SELECT count(*) FROM memberships mm WHERE mm.organization_id=o.id AND mm.role='owner')=1`,
      [userId]
    );
    await query("DELETE FROM users WHERE id=$1", [userId]);
  });
}

// --- organizations / memberships ------------------------------------------
export async function createOrganizationForUser(name, baseSlug, userId) {
  return withTx(async (query) => {
    const slug = await uniqueSlug(query, baseSlug);
    const org = { id: randomUUID(), name, slug, plan: "Free", createdAt: new Date().toISOString() };
    await query("INSERT INTO organizations (id,name,slug,plan,created_at) VALUES ($1,$2,$3,$4,$5)",
      [org.id, org.name, org.slug, org.plan, org.createdAt]);
    await query("INSERT INTO memberships (id,user_id,organization_id,role,created_at) VALUES ($1,$2,$3,$4,$5)",
      [randomUUID(), userId, org.id, "owner", org.createdAt]);
    return org;
  });
}

export async function membershipsForUser(userId) {
  const rows = await q("SELECT * FROM memberships WHERE user_id=$1", [userId]);
  return rows.map(mapMembership);
}

export async function organizationsForUser(userId) {
  const rows = await q(
    `SELECT o.* FROM organizations o
     JOIN memberships m ON m.organization_id=o.id
     WHERE m.user_id=$1 ORDER BY o.created_at`,
    [userId]
  );
  return rows.map(mapOrg);
}

export async function membershipExists(userId, organizationId) {
  const rows = await q("SELECT 1 FROM memberships WHERE user_id=$1 AND organization_id=$2", [userId, organizationId]);
  return rows.length > 0;
}

// --- sessions --------------------------------------------------------------
const MAX_SESSIONS_PER_USER = 5;

export async function createSession({ id, userId, createdAt, expiresAt }) {
  await withTx(async (query) => {
    await query("INSERT INTO sessions (id,user_id,created_at,expires_at) VALUES ($1,$2,$3,$4)", [id, userId, createdAt, expiresAt]);
    await query(
      `DELETE FROM sessions WHERE user_id=$1 AND id NOT IN (
         SELECT id FROM sessions WHERE user_id=$1 ORDER BY created_at DESC, id LIMIT $2
       )`,
      [userId, MAX_SESSIONS_PER_USER]
    );
  });
}

export async function findSession(sessionId) {
  if (!isUuid(sessionId)) return null;
  const rows = await q("SELECT * FROM sessions WHERE id=$1", [sessionId]);
  return mapSession(rows[0]);
}

export async function deleteSession(sessionId) {
  await q("DELETE FROM sessions WHERE id=$1", [sessionId]);
}

export async function sessionsForUser(userId) {
  const rows = await q("SELECT created_at, expires_at FROM sessions WHERE user_id=$1", [userId]);
  return rows.map((r) => ({ createdAt: iso(r.created_at), expiresAt: iso(r.expires_at) }));
}

// --- connector credentials -------------------------------------------------
export async function upsertConnectorCred(cred) {
  await q(
    `INSERT INTO connector_creds (id,provider,organization_id,user_id,access_token,refresh_token,token_type,scope,expires_in,updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     ON CONFLICT (provider, organization_id) DO UPDATE SET
       user_id=EXCLUDED.user_id, access_token=EXCLUDED.access_token, refresh_token=EXCLUDED.refresh_token,
       token_type=EXCLUDED.token_type, scope=EXCLUDED.scope, expires_in=EXCLUDED.expires_in, updated_at=EXCLUDED.updated_at`,
    [cred.id || randomUUID(), cred.provider, cred.organizationId, cred.userId, cred.accessToken,
     cred.refreshToken ?? null, cred.tokenType ?? null, cred.scope ?? null, cred.expiresIn ?? null,
     cred.updatedAt || new Date().toISOString()]
  );
}

export async function deleteConnectorCred(provider, organizationId) {
  await q("DELETE FROM connector_creds WHERE provider=$1 AND organization_id=$2", [provider, organizationId]);
}

export async function findConnectorCred(provider, organizationId) {
  const rows = await q("SELECT * FROM connector_creds WHERE provider=$1 AND organization_id=$2", [provider, organizationId]);
  return mapCred(rows[0]);
}

export async function credsForOrg(organizationId) {
  const rows = await q("SELECT * FROM connector_creds WHERE organization_id=$1", [organizationId]);
  return rows.map(mapCred);
}

export async function credsForExport(userId, orgIds) {
  const rows = await q(
    "SELECT * FROM connector_creds WHERE user_id=$1 OR organization_id = ANY($2::uuid[])",
    [userId, orgIds]
  );
  return rows.map(mapCred);
}

// --- reports ---------------------------------------------------------------
const MAX_REPORTS_PER_ORG = 20;

export async function insertReport(report) {
  await withTx(async (query) => {
    await query(
      "INSERT INTO reports (id,organization_id,source_url,created_at,summary,findings) VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb)",
      [report.id, report.organizationId, report.sourceUrl, report.createdAt,
       JSON.stringify(report.summary ?? null), JSON.stringify(report.findings ?? [])]
    );
    await query(
      `DELETE FROM reports WHERE organization_id=$1 AND id NOT IN (
         SELECT id FROM reports WHERE organization_id=$1 ORDER BY created_at DESC, id LIMIT $2
       )`,
      [report.organizationId, MAX_REPORTS_PER_ORG]
    );
  });
}

export async function findReport(id, organizationId) {
  if (!isUuid(id)) return null; // user-supplied id; avoid a uuid-cast error
  const rows = await q("SELECT * FROM reports WHERE id=$1 AND organization_id=$2", [id, organizationId]);
  return mapReport(rows[0]);
}

// --- login throttling (DB-backed; survives restarts + works across replicas) -
// Records a failed attempt and returns the resulting lock state atomically.
export async function recordLoginFailure(key, maxAttempts, lockoutMs) {
  const rows = await withTx(async (query) => {
    const cur = (await query("SELECT count, lock_until FROM login_attempts WHERE key=$1 FOR UPDATE", [key]))[0];
    const count = (cur?.count || 0) + 1;
    const lockUntil = count >= maxAttempts ? new Date(Date.now() + lockoutMs).toISOString() : null;
    await query(
      `INSERT INTO login_attempts (key,count,lock_until,updated_at) VALUES ($1,$2,$3,now())
       ON CONFLICT (key) DO UPDATE SET count=$2, lock_until=$3, updated_at=now()`,
      [key, count, lockUntil]
    );
    return { count, lockUntil };
  });
  return rows;
}

// Returns remaining lock time in ms, or 0 if not locked. Clears an expired lock.
export async function loginLockRemaining(key) {
  const row = (await q("SELECT lock_until FROM login_attempts WHERE key=$1", [key]))[0];
  if (!row?.lock_until) return 0;
  const remaining = new Date(row.lock_until).getTime() - Date.now();
  if (remaining <= 0) {
    await q("DELETE FROM login_attempts WHERE key=$1", [key]);
    return 0;
  }
  return remaining;
}

export async function clearLoginFailures(key) {
  await q("DELETE FROM login_attempts WHERE key=$1", [key]);
}

// --- auth tokens (email verification + password reset) ---------------------
// Stores only the SHA-256 of the token; the raw token is sent to the user.
export async function createAuthToken({ userId, kind, tokenHash, expiresAt }) {
  const id = randomUUID();
  // One active token per (user, kind): drop older ones first.
  await q("DELETE FROM auth_tokens WHERE user_id=$1 AND kind=$2 AND used_at IS NULL", [userId, kind]);
  await q("INSERT INTO auth_tokens (id,user_id,kind,token_hash,expires_at) VALUES ($1,$2,$3,$4,$5)",
    [id, userId, kind, tokenHash, expiresAt]);
}

// Atomically consumes a token: returns userId if valid/unused/unexpired, else null.
export async function consumeAuthToken(kind, tokenHash) {
  return withTx(async (query) => {
    const row = (await query(
      "SELECT id, user_id, expires_at, used_at FROM auth_tokens WHERE kind=$1 AND token_hash=$2 FOR UPDATE",
      [kind, tokenHash]
    ))[0];
    if (!row || row.used_at) return null;
    if (new Date(row.expires_at).getTime() < Date.now()) return null;
    await query("UPDATE auth_tokens SET used_at=now() WHERE id=$1", [row.id]);
    return row.user_id;
  });
}

export async function deleteUserSessions(userId) {
  await q("DELETE FROM sessions WHERE user_id=$1", [userId]);
}

// --- suppressions (noise control) ------------------------------------------
export async function addSuppression({ organizationId, fingerprint, reason, createdBy }) {
  await q(
    `INSERT INTO suppressions (id,organization_id,fingerprint,reason,created_by) VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (organization_id, fingerprint) DO UPDATE SET reason=EXCLUDED.reason`,
    [randomUUID(), organizationId, fingerprint, reason || null, createdBy || null]
  );
}

export async function removeSuppression(organizationId, fingerprint) {
  await q("DELETE FROM suppressions WHERE organization_id=$1 AND fingerprint=$2", [organizationId, fingerprint]);
}

export async function suppressedFingerprints(organizationId) {
  const rows = await q("SELECT fingerprint FROM suppressions WHERE organization_id=$1", [organizationId]);
  return new Set(rows.map((r) => r.fingerprint));
}

export async function listSuppressions(organizationId) {
  const rows = await q("SELECT fingerprint, reason, created_at FROM suppressions WHERE organization_id=$1 ORDER BY created_at DESC", [organizationId]);
  return rows.map((r) => ({ fingerprint: r.fingerprint, reason: r.reason, createdAt: iso(r.created_at) }));
}

// --- GitHub App installations ----------------------------------------------
export async function setGithubInstallation(organizationId, installationId) {
  await q(
    `INSERT INTO github_installations (organization_id, installation_id) VALUES ($1,$2)
     ON CONFLICT (organization_id) DO UPDATE SET installation_id=EXCLUDED.installation_id, created_at=now()`,
    [organizationId, String(installationId)]
  );
}

export async function getGithubInstallation(organizationId) {
  const rows = await q("SELECT installation_id FROM github_installations WHERE organization_id=$1", [organizationId]);
  return rows[0]?.installation_id || null;
}

export async function removeGithubInstallation(organizationId) {
  await q("DELETE FROM github_installations WHERE organization_id=$1", [organizationId]);
}

// --- background job queue --------------------------------------------------
const mapJob = (r) => r && {
  id: r.id, type: r.type, status: r.status, organizationId: r.organization_id, userId: r.user_id,
  payload: r.payload, result: r.result, error: r.error, attempts: r.attempts,
  createdAt: iso(r.created_at), startedAt: iso(r.started_at), finishedAt: iso(r.finished_at)
};

export async function enqueueJob({ type, organizationId, userId, payload }) {
  const id = randomUUID();
  const rows = await q(
    `INSERT INTO jobs (id,type,organization_id,user_id,payload,status) VALUES ($1,$2,$3,$4,$5::jsonb,'queued')
     RETURNING id, type, status, created_at`,
    [id, type, organizationId, userId || null, JSON.stringify(payload ?? {})]
  );
  return { id: rows[0].id, type: rows[0].type, status: rows[0].status, createdAt: iso(rows[0].created_at) };
}

// Atomically claim the oldest queued job. FOR UPDATE SKIP LOCKED makes this
// safe across concurrent workers / replicas (no job is processed twice).
export async function claimNextJob() {
  return withTx(async (query) => {
    const row = (await query(
      `SELECT * FROM jobs WHERE status='queued' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`
    ))[0];
    if (!row) return null;
    await query("UPDATE jobs SET status='running', started_at=now(), attempts=attempts+1 WHERE id=$1", [row.id]);
    const job = mapJob(row);
    job.status = "running";
    job.attempts = (row.attempts || 0) + 1;
    return job;
  });
}

export async function completeJob(id, result) {
  await q("UPDATE jobs SET status='succeeded', result=$2::jsonb, finished_at=now() WHERE id=$1",
    [id, JSON.stringify(result ?? null)]);
}

export async function failJob(id, error) {
  await q("UPDATE jobs SET status='failed', error=$2, finished_at=now() WHERE id=$1",
    [id, String(error).slice(0, 2000)]);
}

// Re-queue jobs left 'running' by a crashed/restarted worker (or stuck too long).
export async function requeueStaleJobs(staleMs) {
  const cutoff = new Date(Date.now() - staleMs).toISOString();
  const rows = await q(
    "UPDATE jobs SET status='queued', started_at=NULL WHERE status='running' AND started_at < $1 RETURNING id",
    [cutoff]
  );
  return rows.length;
}

export async function getJob(id, organizationId) {
  if (!isUuid(id)) return null;
  const rows = await q("SELECT * FROM jobs WHERE id=$1 AND organization_id=$2", [id, organizationId]);
  return mapJob(rows[0]);
}

export async function recentJobs(organizationId, limit = 20) {
  const rows = await q(
    "SELECT id,type,status,created_at,started_at,finished_at FROM jobs WHERE organization_id=$1 ORDER BY created_at DESC LIMIT $2",
    [organizationId, limit]
  );
  return rows.map((r) => ({ id: r.id, type: r.type, status: r.status, createdAt: iso(r.created_at), startedAt: iso(r.started_at), finishedAt: iso(r.finished_at) }));
}
