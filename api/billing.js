import { createHmac, timingSafeEqual } from "node:crypto";
import { json, entitlements, planFor, resolveOrgContext, appBaseUrl } from "./_lib.js";
import * as repo from "./_repo.js";
import { logger } from "./_log.js";
import { fetchWithTimeout } from "./_http.js";

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
    // S2: also stamp the org id on the SUBSCRIPTION (Stripe does NOT copy the
    // Checkout Session metadata onto the subscription object), so a later
    // customer.subscription.deleted webhook can resolve the org to downgrade.
    "subscription_data[metadata][organizationId]": context.organization.id,
    success_url: `${appBaseUrl(req)}/?upgraded=1`,
    cancel_url: `${appBaseUrl(req)}/?upgrade=cancelled`
  });
  const r = await fetchWithTimeout("https://api.stripe.com/v1/checkout/sessions", {
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

  // S1: idempotency. Record the event id first; if it was already processed
  // (replay within the signature tolerance window), ack 200 WITHOUT re-running
  // side effects. Events without an id (shouldn't happen) skip the gate.
  if (event.id) {
    let firstSeen;
    try {
      firstSeen = await repo.recordStripeEvent(event.id);
    } catch (err) {
      logger.error("billing.event_record_failed", { err });
      json(res, 500, { error: "Webhook processing error." });
      return;
    }
    if (!firstSeen) {
      logger.info("billing.event_replayed", { eventId: event.id, type: event.type });
      json(res, 200, { received: true });
      return;
    }
  }

  try {
    if (event.type === "checkout.session.completed") {
      const obj = event.data?.object || {};
      const orgId = obj.metadata?.organizationId || obj.client_reference_id;
      if (orgId) {
        await repo.setOrgPlan(orgId, "Pro");
        // S2: persist the Stripe customer so subscription.deleted can resolve the
        // org even though Stripe won't echo the session metadata there.
        if (obj.customer) { try { await repo.setOrgStripeCustomer(orgId, obj.customer); } catch (err) { logger.error("billing.customer_link_failed", { err }); } }
        logger.info("billing.upgraded", { orgId });
      }
    } else if (event.type === "customer.subscription.deleted") {
      const obj = event.data?.object || {};
      // S2: prefer subscription metadata; fall back to resolving by customer id.
      let orgId = obj.metadata?.organizationId;
      if (!orgId && obj.customer) {
        const org = await repo.findOrgByStripeCustomer(obj.customer);
        orgId = org?.id || null;
      }
      if (orgId) { await repo.setOrgPlan(orgId, "Free"); logger.info("billing.downgraded", { orgId }); }
      else logger.warn("billing.downgrade_unresolved", { customer: obj.customer || null });
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
    const expose = error?.expose === true;
    const statusCode = expose ? error.statusCode || 400 : 500;
    if (!expose) logger.error("billing.handler_error", { action, err: error });
    json(res, statusCode, { error: expose ? error.message : "Request failed." });
  }
}
