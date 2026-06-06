import { randomUUID, randomBytes, createHash } from "node:crypto";
import { json, readBody } from "./_lib.js";
import * as repo from "./_repo.js";
import { sendVerificationEmail, sendPasswordResetEmail, emailConfigured } from "./_email.js";
import {
  buildSessionCookie,
  clearSessionCookie,
  createSession,
  currentUserContext,
  destroySession,
  hashPassword,
  isProductionLike,
  passwordNeedsUpgrade,
  publicOrganization,
  publicUser,
  slugify,
  verifyPassword,
  verifySessionToken
} from "./_auth.js";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
const VERIFY_TTL_MS = 24 * 60 * 60 * 1000;
const RESET_TTL_MS = 60 * 60 * 1000;

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function clientKey(req, email) {
  const fwd = req.headers["x-forwarded-for"] || "";
  const ip = String(fwd).split(",")[0].trim() || req.socket?.remoteAddress || "unknown";
  return `${ip}|${email}`;
}

// A second lockout bucket keyed on the email ALONE. The per-(ip,email) bucket is
// defeatable by rotating the spoofable X-Forwarded-For header, so this account-
// wide bucket (with a higher threshold to tolerate legit multi-device logins)
// throttles distributed online guessing against a single account.
function accountKey(email) {
  return `acct|${email}`;
}
const ACCOUNT_MAX_ATTEMPTS = 15;

// Email verification is enforced when we can actually send mail, or when
// explicitly required. Without a provider we don't lock users out of a feature
// they could never unlock, so signups are auto-verified in that case.
function emailVerificationRequired() {
  return emailConfigured() || process.env.CODECANIC_REQUIRE_EMAIL_VERIFICATION === "1";
}

function baseUrl(req) {
  if (process.env.CODECANIC_APP_URL) return process.env.CODECANIC_APP_URL.replace(/\/$/, "");
  // Don't trust the Host header for password-reset/verification links in prod —
  // a forged Host would point token links at an attacker domain.
  if (isProductionLike()) return "https://codecanic.app";
  const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0];
  return `${proto}://${req.headers.host || "localhost"}`;
}

const hashToken = (raw) => createHash("sha256").update(raw).digest("hex");
const newToken = () => randomBytes(32).toString("base64url");

// Validates the shared password policy. Returns an error string or null.
function passwordPolicyError(password) {
  if (password.length < 15) return "Password must be at least 15 characters.";
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Password must include uppercase, lowercase, a digit, and a symbol.";
  }
  return null;
}

async function issueVerification(user, req) {
  const raw = newToken();
  await repo.createAuthToken({
    userId: user.id, kind: "email_verify", tokenHash: hashToken(raw),
    expiresAt: new Date(Date.now() + VERIFY_TTL_MS).toISOString()
  });
  const link = `${baseUrl(req)}/api/auth/verify-email?token=${raw}`;
  try { await sendVerificationEmail(user.email, link); } catch (err) { console.error("[verify email]", err.message); }
  // Only exposed in non-production so the flow is testable without a provider.
  return isProductionLike() ? undefined : raw;
}

async function signup(req, res) {
  const body = await readBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const name = String(body.name || "").trim() || email.split("@")[0];
  const orgName = String(body.organization || `${name}'s workspace`).trim();

  if (!emailRegex.test(email)) {
    json(res, 400, { error: "Enter a valid email address." });
    return;
  }
  const pwErr = passwordPolicyError(password);
  if (pwErr) {
    json(res, 400, { error: pwErr });
    return;
  }
  if (body.acceptTerms !== true) {
    json(res, 400, { error: "You must accept the Terms of Service and Privacy Policy to create an account." });
    return;
  }
  const age = Number(body.age);
  if (!Number.isFinite(age) || age < 16) {
    json(res, 400, { error: "You must confirm you are 16 or older to create an account (GDPR digital age of consent)." });
    return;
  }

  if (await repo.findUserByEmail(email)) {
    json(res, 409, { error: "An account with that email already exists." });
    return;
  }

  const passwordHash = await hashPassword(password);
  const now = new Date().toISOString();
  const mustVerify = emailVerificationRequired();
  const user = {
    id: randomUUID(),
    email,
    name,
    passwordHash,
    createdAt: now,
    termsAcceptedAt: now,
    privacyAcceptedAt: now,
    marketingOptIn: body.marketingOptIn === true,
    ageConfirmed: true,
    emailVerified: !mustVerify
  };

  let createdOrg;
  try {
    ({ organization: createdOrg } = await repo.createUserWithOrg(user, slugify(orgName), orgName));
  } catch (err) {
    // Unique-email race backstop (explicit check above handles the common case).
    if (/unique|duplicate/i.test(err.message)) {
      json(res, 409, { error: "An account with that email already exists." });
      return;
    }
    throw err;
  }

  const devVerifyToken = mustVerify ? await issueVerification(user, req) : undefined;

  const token = await createSession(user.id);
  res.setHeader("Set-Cookie", buildSessionCookie(token));
  json(res, 200, {
    user: publicUser(user),
    organizations: [publicOrganization(createdOrg)],
    activeOrganization: publicOrganization(createdOrg),
    emailVerificationRequired: mustVerify,
    ...(devVerifyToken ? { devVerifyToken } : {})
  });
}

async function login(req, res) {
  const body = await readBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const key = clientKey(req, email);
  const acctKey = accountKey(email);

  const lockMs = Math.max(await repo.loginLockRemaining(key), await repo.loginLockRemaining(acctKey));
  if (lockMs > 0) {
    const retryAfter = Math.ceil(lockMs / 1000);
    res.setHeader("Retry-After", String(retryAfter));
    json(res, 429, { error: `Too many failed attempts. Try again in ${retryAfter}s.` });
    return;
  }

  const user = await repo.findUserByEmail(email);
  const ok = user ? await verifyPassword(password, user.passwordHash) : false;
  if (!user || !ok) {
    await repo.recordLoginFailure(key, LOGIN_MAX_ATTEMPTS, LOGIN_LOCKOUT_MS);
    await repo.recordLoginFailure(acctKey, ACCOUNT_MAX_ATTEMPTS, LOGIN_LOCKOUT_MS);
    json(res, 401, { error: "Email or password is incorrect." });
    return;
  }
  await repo.clearLoginFailures(key);
  await repo.clearLoginFailures(acctKey);

  // Transparently upgrade legacy/low-cost password hashes on successful login.
  if (passwordNeedsUpgrade(user.passwordHash)) {
    try { await repo.updateUserPassword(user.id, await hashPassword(password)); } catch (err) { console.error("[rehash]", err.message); }
  }

  const organizations = (await repo.organizationsForUser(user.id)).map(publicOrganization);

  const token = await createSession(user.id);
  res.setHeader("Set-Cookie", buildSessionCookie(token));
  json(res, 200, {
    user: publicUser(user),
    organizations,
    activeOrganization: organizations[0] || null
  });
}

async function logout(req, res) {
  const cookieHeader = req.headers.cookie || "";
  const token = cookieHeader
    .split(";")
    .map((pair) => pair.trim())
    .find((pair) => pair.startsWith("codecanic_session="));
  if (token) {
    const value = decodeURIComponent(token.split("=")[1] || "");
    const sessionId = verifySessionToken(value);
    if (sessionId) await destroySession(sessionId);
  }
  res.setHeader("Set-Cookie", clearSessionCookie());
  json(res, 200, { status: "signed_out" });
}

async function exportData(req, res) {
  const ctx = await currentUserContext(req);
  if (!ctx) {
    json(res, 401, { error: "Sign in to export your data." });
    return;
  }
  const userId = ctx.user.id;
  const [myMemberships, myOrgs, mySessions] = await Promise.all([
    repo.membershipsForUser(userId),
    repo.organizationsForUser(userId),
    repo.sessionsForUser(userId)
  ]);
  const myOrgIds = myOrgs.map((o) => o.id);
  const creds = await repo.credsForExport(userId, myOrgIds);
  const payload = {
    exportedAt: new Date().toISOString(),
    notice:
      "This file contains personal data Codecanic stores about your account. Provider access tokens are redacted for safety. To revoke them, disconnect via the Connection Wizard or contact support.",
    user: {
      id: ctx.user.id,
      email: ctx.user.email,
      name: ctx.user.name,
      createdAt: ctx.user.createdAt,
      termsAcceptedAt: ctx.user.termsAcceptedAt || null,
      privacyAcceptedAt: ctx.user.privacyAcceptedAt || null,
      marketingOptIn: ctx.user.marketingOptIn === true
    },
    organizations: myOrgs.map(publicOrganization),
    memberships: myMemberships.map((m) => ({
      organizationId: m.organizationId,
      role: m.role,
      createdAt: m.createdAt
    })),
    connectorCredentials: creds.map((c) => ({
      provider: c.provider,
      organizationId: c.organizationId,
      tokenType: c.tokenType,
      scope: c.scope,
      updatedAt: c.updatedAt,
      accessToken: "***redacted***",
      refreshToken: c.refreshToken ? "***redacted***" : null
    })),
    activeSessions: mySessions
  };
  res.setHeader("Content-Disposition", 'attachment; filename="codecanic-data-export.json"');
  json(res, 200, payload);
}

async function deleteAccount(req, res) {
  const ctx = await currentUserContext(req);
  if (!ctx) {
    json(res, 401, { error: "Sign in to delete your account." });
    return;
  }
  const body = await readBody(req);
  const password = String(body.password || "");
  const confirm = String(body.confirm || "").trim().toUpperCase();
  if (!password) {
    json(res, 422, { error: "Re-enter your password to confirm." });
    return;
  }
  if (confirm !== "DELETE") {
    json(res, 422, { error: 'Type "DELETE" exactly to confirm.' });
    return;
  }
  const ok = await verifyPassword(password, ctx.user.passwordHash);
  if (!ok) {
    json(res, 401, { error: "Password is incorrect." });
    return;
  }

  await repo.deleteUserAndSoleOwnedOrgs(ctx.user.id);

  res.setHeader("Set-Cookie", clearSessionCookie());
  json(res, 200, { status: "account_deleted" });
}

async function me(req, res) {
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 200, { user: null, organizations: [] });
    return;
  }
  json(res, 200, {
    user: publicUser(context.user),
    organizations: context.organizations.map(publicOrganization)
  });
}

function verifiedHtml(title, message, okState) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head>
<body style="font-family:system-ui;padding:32px;background:#0a1019;color:#f8fafc;">
<h1 style="color:${okState ? "#14b8a6" : "#f87171"};">${title}</h1>
<p>${message}</p>
<p><a href="/" style="color:#2dd4bf;">Return to Codecanic</a></p>
</body></html>`;
}

async function verifyEmail(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  // Accept the token from the email link (GET ?token=) or a JSON body (POST).
  let raw = url.searchParams.get("token");
  if (!raw && req.method === "POST") raw = String((await readBody(req)).token || "");
  const userId = raw ? await repo.consumeAuthToken("email_verify", hashToken(raw)) : null;
  if (userId) await repo.markEmailVerified(userId);

  if (req.method === "GET") {
    res.writeHead(userId ? 200 : 400, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(userId
      ? verifiedHtml("Email verified", "Your email is confirmed. You can start scanning repositories.", true)
      : verifiedHtml("Verification failed", "This link is invalid or has expired. Sign in and request a new one.", false));
    return;
  }
  if (!userId) {
    json(res, 400, { error: "This verification link is invalid or has expired." });
    return;
  }
  json(res, 200, { status: "email_verified" });
}

async function resendVerification(req, res) {
  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in to resend verification." });
    return;
  }
  if (context.user.emailVerified) {
    json(res, 200, { status: "already_verified" });
    return;
  }
  const devToken = await issueVerification(context.user, req);
  json(res, 200, { status: "verification_sent", ...(devToken ? { devVerifyToken: devToken } : {}) });
}

async function requestPasswordReset(req, res) {
  const email = normalizeEmail((await readBody(req)).email);
  let devToken;
  const user = email ? await repo.findUserByEmail(email) : null;
  if (user) {
    const raw = newToken();
    await repo.createAuthToken({
      userId: user.id, kind: "password_reset", tokenHash: hashToken(raw),
      expiresAt: new Date(Date.now() + RESET_TTL_MS).toISOString()
    });
    const link = `${baseUrl(req)}/reset-password?token=${raw}`;
    try { await sendPasswordResetEmail(user.email, link); } catch (err) { console.error("[reset email]", err.message); }
    if (!isProductionLike()) devToken = raw;
  }
  // Always generic to prevent account enumeration.
  json(res, 200, { status: "reset_requested", message: "If an account exists for that email, a reset link has been sent.", ...(devToken ? { devResetToken: devToken } : {}) });
}

async function resetPassword(req, res) {
  const body = await readBody(req);
  const raw = String(body.token || "");
  const password = String(body.password || "");
  const pwErr = passwordPolicyError(password);
  if (pwErr) {
    json(res, 400, { error: pwErr });
    return;
  }
  const userId = raw ? await repo.consumeAuthToken("password_reset", hashToken(raw)) : null;
  if (!userId) {
    json(res, 400, { error: "This reset link is invalid or has expired." });
    return;
  }
  await repo.updateUserPassword(userId, await hashPassword(password));
  // Invalidate all existing sessions so a leaked session can't outlive a reset.
  await repo.deleteUserSessions(userId);
  res.setHeader("Set-Cookie", clearSessionCookie());
  json(res, 200, { status: "password_reset" });
}

export default async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const action = url.pathname.replace(/^\/api\/auth\/?/, "");
  try {
    if (action === "signup" && req.method === "POST") return await signup(req, res);
    if (action === "login" && req.method === "POST") return await login(req, res);
    if (action === "logout" && req.method === "POST") return await logout(req, res);
    if (action === "me" && req.method === "GET") return await me(req, res);
    if (action === "verify-email" && (req.method === "GET" || req.method === "POST")) return await verifyEmail(req, res);
    if (action === "resend-verification" && req.method === "POST") return await resendVerification(req, res);
    if (action === "request-password-reset" && req.method === "POST") return await requestPasswordReset(req, res);
    if (action === "reset-password" && req.method === "POST") return await resetPassword(req, res);
    if (action === "account" && (req.method === "DELETE" || req.method === "POST")) {
      return await deleteAccount(req, res);
    }
    if (action === "export" && req.method === "GET") return await exportData(req, res);
    json(res, 404, { error: "Unknown auth action" });
  } catch (error) {
    console.error("[auth error]", error);
    const isClientError = /^(Request body|Provider|Apple|Railway|Password|Email|Enter|At least|Sign in|Type "DELETE"|Re-enter|You|CODECANIC_SESSION_SECRET)/.test(
      error?.message || ""
    );
    json(res, isClientError ? 400 : 500, {
      error: isClientError ? error.message : "Request failed."
    });
  }
}
