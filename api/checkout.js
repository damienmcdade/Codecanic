import { json, readBody } from "./_lib.js";

const priceEnv = {
  Basic: "STRIPE_BASIC_PRICE_ID",
  Pro: "STRIPE_PRO_PRICE_ID",
  Max: "STRIPE_MAX_PRICE_ID"
};

export default async function handler(req, res) {
  if (req.method !== "POST") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }

  try {
    const body = await readBody(req);
    const plan = body.plan;
    if (plan === "Free") {
      json(res, 200, { plan, status: "free_plan_active" });
      return;
    }

    const stripeSecret = process.env.STRIPE_SECRET_KEY;
    const priceId = process.env[priceEnv[plan]];
    if (!stripeSecret || !priceId) {
      json(res, 200, {
        plan,
        status: "configuration_required",
        requiredEnv: ["STRIPE_SECRET_KEY", priceEnv[plan]].filter(Boolean),
        message: "Stripe checkout is wired. Add the Stripe environment variables to create live sessions."
      });
      return;
    }

    const origin = req.headers.origin || `https://${req.headers.host}`;
    const params = new URLSearchParams({
      mode: "subscription",
      "line_items[0][price]": priceId,
      "line_items[0][quantity]": "1",
      success_url: `${origin}?checkout=success&plan=${encodeURIComponent(plan)}`,
      cancel_url: `${origin}?checkout=cancelled`
    });

    const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${stripeSecret}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params
    });
    const data = await response.json();

    if (!response.ok) {
      json(res, response.status, { error: data.error?.message || "Stripe checkout failed." });
      return;
    }

    json(res, 200, { plan, status: "checkout_ready", url: data.url });
  } catch (error) {
    json(res, 400, { error: error.message });
  }
}
