import { getConnector, json } from "./_lib.js";
import { randomUUID } from "node:crypto";

export default function handler(req, res) {
  if (req.method !== "GET") {
    json(res, 405, { error: "Method not allowed" });
    return;
  }

  const url = new URL(req.url, `https://${req.headers.host || "codecanic.local"}`);
  const name = url.searchParams.get("name");
  const connector = getConnector(name);

  if (!connector) {
    json(res, 404, { error: "Unknown connector" });
    return;
  }

  const configured = Boolean(process.env[connector.env]);
  const redirectUri =
    process.env.CODECANIC_REDIRECT_URI ||
    `${url.origin}/api/oauth/callback?provider=${encodeURIComponent(name)}`;

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

  const authUrl = new URL(connector.authBase);
  if (name !== "Railway" && name !== "Xcode") {
    authUrl.searchParams.set("client_id", process.env[connector.env]);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("state", randomUUID());
    if (connector.scopes) authUrl.searchParams.set("scope", connector.scopes);
    if (name === "GitLab") authUrl.searchParams.set("response_type", "code");
  }

  json(res, 200, {
    name,
    configured,
    status: "authorization_ready",
    authUrl: authUrl.toString()
  });
}
