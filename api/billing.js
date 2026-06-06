import { createHmac, timingSafeEqual } from "node:crypto";
import { json, entitlements, planFor, resolveOrgContext } from "./_lib.js";
import * as repo from "./_repo.js";
import { logger } from "./_log.js";
import { isProductionLike } from "./_auth.js";

// Codecanic stays free + ad-supported; Pro is an optional paid upgrade
// (ad-free + unlimited scans). Stripe is used when configured; without keys,
// checkout reports "not configured" rather than failing.
function billingConfigured() {
  return Boolean(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_PRO_PRICE_ID);
}

function readRaw(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (c) => { body += c; if (body.length > 1_000_000) reject(new Error("Body too large.")); });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function appUrl(req) {
  if (process.env.CODECANIC_APP_URL) return process.env.CODECANIC_APP_URL.replace(/\/$/, "");
  // Stripe success/cancel URLs must not be derived from a forged Host in prod.
  if (isProductionLike()) return "https://codecanic.app";
  const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0];
  return `${proto}://${req.headers.host || "localhost"}`;
}

async function status(req, res, context) {
  const usage = await repo.countScansThisMonth(context.organization.id);
  const plan = planFor(context.organization.plan);
  json(res, 200, {
    plan: plan.name,
    entitlements: entitlements(context.organization.plan),
    usage: { scansThisMonth: usage, monthlyScanLimit: plan.monthlyScanLimit },
    billingConfigured: billingConfigured()
  });
}

async function checkout(req, res, context) {
  if (!billingConfigured()) {
    json(res, 200, { configured: false, message: "Billing is not configured on this deployment." });
    return;
  }
  // Create a Stripe Checkout Session via the REST API (no SDK dependency).
  const form = new URLSearchParams({
    mode: "subscription",
    "line_items[0][price]": process.env.STRIPE_PRO_PRICE_ID,
    "line_items[0][quantity]": "1",
    client_reference_id: context.organization.id,
    "metadata[organizationId]": context.organization.id,
    success_url: `${appUrl(req)}/?upgraded=1`,
    cancel_url: `${appUrl(req)}/?upgrade=cancelled`
  });
  const r = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.STRIPE_SECRET_KEY}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: form
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    json(res, 502, { error: `Stripe checkout failed (${r.status}): ${data.error?.message || "unknown"}` });
    return;
  }
  json(res, 200, { url: data.url });
}

// Verify Stripe's webhook signature: v1 = HMAC-SHA256(`${t}.${rawBody}`, secret).
// Also enforces a timestamp tolerance (default 5 min) so a captured event can't
// be replayed indefinitely. Pass toleranceSec=0 to disable the time check.
export function verifyStripeSignature(rawBody, sigHeader, secret, toleranceSec = 300) {
  if (!sigHeader || !secret) return false;
  const parts = Object.fromEntries(sigHeader.split(",").map((kv) => kv.split("=")));
  if (!parts.t || !parts.v1) return false;
  if (toleranceSec > 0) {
    const ts = Number(parts.t);
    if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > toleranceSec) return false;
  }
  const expected = createHmac("sha256", secret).update(`${parts.t}.${rawBody}`).digest("hex");
  const a = Buffer.from(parts.v1), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function webhook(req, res) {
  const raw = await readRaw(req);
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret || !verifyStripeSignature(raw, req.headers["stripe-signature"], secret)) {
    json(res, 400, { error: "Invalid webhook signature." });
    return;
  }
  let event;
  try { event = JSON.parse(raw); } catch { json(res, 400, { error: "Invalid payload." }); return; }
  try {
    if (event.type === "checkout.session.completed") {
      const orgId = event.data?.object?.metadata?.organizationId || event.data?.object?.client_reference_id;
      if (orgId) { await repo.setOrgPlan(orgId, "Pro"); logger.info("billing.upgraded", { orgId }); }
    } else if (event.type === "customer.subscription.deleted") {
      const orgId = event.data?.object?.metadata?.organizationId;
      if (orgId) { await repo.setOrgPlan(orgId, "Free"); logger.info("billing.downgraded", { orgId }); }
    }
  } catch (err) {
    logger.error("billing.webhook_error", { err });
  }
  json(res, 200, { received: true });
}

export default async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const action = url.pathname.replace(/^\/api\/billing\/?/, "");
  try {
    // Webhook is unauthenticated (Stripe-signed) and must not require an org.
    if (action === "webhook" && req.method === "POST") return await webhook(req, res);

    const context = await resolveOrgContext(req);
    if (!context.authenticated) { json(res, 401, { error: "Sign in required." }); return; }
    if (!context.organization) { json(res, 400, { error: "Select an organization first." }); return; }

    if (action === "" && req.method === "GET") return await status(req, res, context);
    if (action === "checkout" && req.method === "POST") return await checkout(req, res, context);
    json(res, 404, { error: "Unknown billing action" });
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
