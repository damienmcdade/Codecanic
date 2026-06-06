import { createHmac, randomBytes, randomUUID, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import * as repo from "./_repo.js";

const scryptAsync = promisify(scrypt);
const SESSION_DAYS = 14;
const SESSION_COOKIE = "codecanic_session";
const KEY_LENGTH = 64;

export function isProductionLike() {
  return Boolean(
    process.env.NODE_ENV === "production" ||
      process.env.VERCEL === "1" ||
      process.env.RAILWAY_ENVIRONMENT ||
      process.env.RAILWAY_PROJECT_ID
  );
}

const DEV_FALLBACK_SECRET = "codecanic-development-secret-do-not-use-in-prod";

export function secret() {
  const value = process.env.CODECANIC_SESSION_SECRET;
  if (value && value.length >= 32 && value !== DEV_FALLBACK_SECRET) return value;
  if (isProductionLike()) {
    throw new Error(
      "CODECANIC_SESSION_SECRET must be set to a 32+ character value in production. Refusing to use insecure fallback."
    );
  }
  return value || DEV_FALLBACK_SECRET;
}

export function slugify(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || `org-${randomBytes(3).toString("hex")}`;
}

// scrypt cost parameters. Raised from Node's default (N=16384) toward the OWASP
// 2025 bar. Params are encoded in the stored hash so old hashes still verify and
// can be transparently upgraded on the next successful login.
const SCRYPT = { N: 65536, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

export async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const derived = await scryptAsync(password, salt, KEY_LENGTH, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt}$${derived.toString("hex")}`;
}

export async function verifyPassword(password, stored) {
  if (!stored || typeof stored !== "string") return false;
  let salt, hex, opts;
  if (stored.startsWith("scrypt$")) {
    const [, N, r, p, s, h] = stored.split("$");
    if (!s || !h) return false;
    salt = s; hex = h;
    opts = { N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem };
  } else if (stored.includes(":")) {
    // Legacy format: "<saltHex>:<hashHex>" hashed with Node's scrypt defaults.
    [salt, hex] = stored.split(":");
    opts = undefined;
  } else {
    return false;
  }
  const derived = await scryptAsync(password, salt, KEY_LENGTH, opts);
  const expected = Buffer.from(hex, "hex");
  if (expected.length !== derived.length) return false;
  return timingSafeEqual(expected, derived);
}

// True when a stored hash is below the current cost target and should be
// re-hashed (legacy format, or a smaller N).
export function passwordNeedsUpgrade(stored) {
  if (typeof stored !== "string") return false;
  if (!stored.startsWith("scrypt$")) return true;
  const n = Number(stored.split("$")[1]);
  return !Number.isFinite(n) || n < SCRYPT.N;
}

function sign(value) {
  return createHmac("sha256", secret()).update(value).digest("hex");
}

export function signSessionToken(sessionId) {
  return `${sessionId}.${sign(sessionId)}`;
}

export function verifySessionToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [sessionId, signature] = token.split(".");
  const expected = sign(sessionId);
  if (signature.length !== expected.length) return null;
  if (!timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(expected, "hex"))) return null;
  return sessionId;
}

export function parseCookies(header = "") {
  return Object.fromEntries(
    header
      .split(";")
      .map((pair) => pair.trim())
      .filter(Boolean)
      .map((pair) => {
        const idx = pair.indexOf("=");
        if (idx === -1) return [pair, ""];
        return [pair.slice(0, idx), decodeURIComponent(pair.slice(idx + 1))];
      })
  );
}

export function buildSessionCookie(token, { maxAgeDays = SESSION_DAYS, secure } = {}) {
  const attrs = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.floor(maxAgeDays * 86400)}`
  ];
  if (secure ?? isProductionLike()) attrs.push("Secure");
  return attrs.join("; ");
}

export function clearSessionCookie() {
  const attrs = [`${SESSION_COOKIE}=`, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
  if (isProductionLike()) attrs.push("Secure");
  return attrs.join("; ");
}

export async function createSession(userId) {
  const sessionId = randomUUID();
  await repo.createSession({
    id: sessionId,
    userId,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + SESSION_DAYS * 86400_000).toISOString()
  });
  return signSessionToken(sessionId);
}

export async function destroySession(sessionId) {
  await repo.deleteSession(sessionId);
}

export async function currentSession(req) {
  const cookies = parseCookies(req.headers.cookie || "");
  const token = cookies[SESSION_COOKIE];
  const sessionId = verifySessionToken(token);
  if (!sessionId) return null;
  const session = await repo.findSession(sessionId);
  if (!session) return null;
  if (new Date(session.expiresAt).getTime() < Date.now()) return null;
  const user = await repo.findUserById(session.userId);
  if (!user) return null;
  return { session, user };
}

export async function currentUserContext(req) {
  const auth = await currentSession(req);
  if (!auth) return null;
  const [memberships, organizations] = await Promise.all([
    repo.membershipsForUser(auth.user.id),
    repo.organizationsForUser(auth.user.id)
  ]);
  return { ...auth, memberships, organizations };
}

export function publicUser(user) {
  if (!user) return null;
  const { id, email, name, createdAt, emailVerified } = user;
  return { id, email, name, createdAt, emailVerified: emailVerified === true };
}

export function publicOrganization(org) {
  if (!org) return null;
  const { id, name, slug, plan, createdAt } = org;
  return { id, name, slug, plan, createdAt };
}
