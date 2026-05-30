import { randomUUID } from "node:crypto";
import { json, readBody } from "./_lib.js";
import * as repo from "./_repo.js";
import {
  buildSessionCookie,
  clearSessionCookie,
  createSession,
  currentUserContext,
  destroySession,
  hashPassword,
  publicOrganization,
  publicUser,
  slugify,
  verifyPassword,
  verifySessionToken
} from "./_auth.js";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
const loginAttempts = new Map();

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function clientKey(req, email) {
  const fwd = req.headers["x-forwarded-for"] || "";
  const ip = String(fwd).split(",")[0].trim() || req.socket?.remoteAddress || "unknown";
  return `${ip}|${email}`;
}

function checkLoginLockout(key) {
  const entry = loginAttempts.get(key);
  if (!entry) return null;
  const now = Date.now();
  if (entry.lockUntil && entry.lockUntil > now) {
    return { retryAfterMs: entry.lockUntil - now };
  }
  if (entry.lockUntil && entry.lockUntil <= now) {
    loginAttempts.delete(key);
  }
  return null;
}

function recordLoginFailure(key) {
  const now = Date.now();
  const entry = loginAttempts.get(key) || { count: 0, lockUntil: 0 };
  entry.count += 1;
  if (entry.count >= LOGIN_MAX_ATTEMPTS) {
    entry.lockUntil = now + LOGIN_LOCKOUT_MS;
  }
  loginAttempts.set(key, entry);
}

function clearLoginFailures(key) {
  loginAttempts.delete(key);
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
  if (password.length < 15) {
    json(res, 400, { error: "Password must be at least 15 characters." });
    return;
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    json(res, 400, {
      error: "Password must include uppercase, lowercase, a digit, and a symbol."
    });
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
  const user = {
    id: randomUUID(),
    email,
    name,
    passwordHash,
    createdAt: now,
    termsAcceptedAt: now,
    privacyAcceptedAt: now,
    marketingOptIn: body.marketingOptIn === true,
    ageConfirmed: true
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

  const token = await createSession(user.id);
  res.setHeader("Set-Cookie", buildSessionCookie(token));
  json(res, 200, {
    user: publicUser(user),
    organizations: [publicOrganization(createdOrg)],
    activeOrganization: publicOrganization(createdOrg)
  });
}

async function login(req, res) {
  const body = await readBody(req);
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const key = clientKey(req, email);

  const lockout = checkLoginLockout(key);
  if (lockout) {
    const retryAfter = Math.ceil(lockout.retryAfterMs / 1000);
    res.setHeader("Retry-After", String(retryAfter));
    json(res, 429, { error: `Too many failed attempts. Try again in ${retryAfter}s.` });
    return;
  }

  const user = await repo.findUserByEmail(email);
  const ok = user ? await verifyPassword(password, user.passwordHash) : false;
  if (!user || !ok) {
    recordLoginFailure(key);
    json(res, 401, { error: "Email or password is incorrect." });
    return;
  }
  clearLoginFailures(key);

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

export default async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const action = url.pathname.replace(/^\/api\/auth\/?/, "");
  try {
    if (action === "signup" && req.method === "POST") return await signup(req, res);
    if (action === "login" && req.method === "POST") return await login(req, res);
    if (action === "logout" && req.method === "POST") return await logout(req, res);
    if (action === "me" && req.method === "GET") return await me(req, res);
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
