import { createHmac, randomUUID } from "node:crypto";
import { getConnector, json } from "./_lib.js";
import { currentUserContext } from "./_auth.js";

function signState(payload) {
  const secret = process.env.CODECANIC_SESSION_SECRET || "codecanic-development-secret-do-not-use-in-prod";
  const value = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(value).digest("base64url");
  return `${value}.${signature}`;
}

export default async function handler(req, res) {
  if (req.method !== "GET") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const name = url.searchParams.get("name");
  const connector = getConnector(name);

  if (!connector) {
    json(res, 404, { error: "Unknown connector" });
    return;
  }

  const configured = Boolean(process.env[connector.env]);
  const protocol = req.headers["x-forwarded-proto"] || (url.protocol === "https:" ? "https" : "http");
  const host = req.headers.host || "codecanic.local";
  const defaultRedirect = `${protocol}://${host}/api/oauth/callback?provider=${encodeURIComponent(name)}`;
  const redirectUri = process.env.CODECANIC_REDIRECT_URI || defaultRedirect;

  if (!configured) {
    json(res, 200, {
      name,
      configured,
      status: "configuration_required",
      requiredEnv: connector.env,
      message: `${name} needs ${connector.env} before live authorization can start.`
    });
    return;
  }

  if (name === "Railway" || name === "Xcode") {
    json(res, 200, {
      name,
      configured,
      status: "manual_token_required",
      message: `${name} uses a manual token. Paste a personal access token in settings.`
    });
    return;
  }

  const context = await currentUserContext(req);
  if (!context) {
    json(res, 401, { error: "Sign in to begin authorization." });
    return;
  }

  const requestedOrg = req.headers["x-codecanic-org"] || url.searchParams.get("organization");
  const organization = requestedOrg
    ? context.organizations.find((org) => org.slug === requestedOrg || org.id === requestedOrg)
    : context.organizations[0];
  if (!organization) {
    json(res, 400, { error: "Select an organization first." });
    return;
  }

  const state = signState({
    nonce: randomUUID(),
    userId: context.user.id,
    organizationId: organization.id,
    provider: name,
    expiresAt: Date.now() + 10 * 60_000
  });

  const authUrl = new URL(connector.authBase);
  authUrl.searchParams.set("client_id", process.env[connector.env]);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("state", state);
  if (connector.scopes) authUrl.searchParams.set("scope", connector.scopes);
  if (name === "GitLab") authUrl.searchParams.set("response_type", "code");

  json(res, 200, {
    name,
    configured,
    status: "authorization_ready",
    authUrl: authUrl.toString()
  });
}
