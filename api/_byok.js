// Bring-your-own-key (BYOK).
//
// AI-powered code repairs run on the END USER's own AI provider key, never
// Codecanic's. The key arrives per-request as an HTTP header, is used to make
// the provider call inline, and is NEVER written to the database, a job
// payload, a log line, or an API response. This shifts inference cost to the
// user who supplied the key and keeps us out of the business of holding model
// credentials.
//
// Storage of the key is the browser's job (localStorage) — see the "AI Keys"
// panel in the web app. The server only ever sees it for the lifetime of one
// request.
import { ClientError } from "./_lib.js";

/** The user's Anthropic key for this request, or "" if none was sent. */
export function userAnthropicKey(req) {
  return String(req.headers?.["x-anthropic-key"] || "").trim();
}

/** The user's OpenAI key for this request (optional), or "" if none was sent. */
export function userOpenAiKey(req) {
  return String(req.headers?.["x-openai-key"] || "").trim();
}

/**
 * Require a syntactically valid Anthropic key on the request. Throws a
 * client-safe error (with a machine code the UI uses to pop the key panel)
 * when absent or malformed. Returns the key on success.
 */
export function requireAnthropicKey(req) {
  const key = userAnthropicKey(req);
  if (!key || !/^sk-ant-[A-Za-z0-9_-]{10,}$/.test(key)) {
    const err = new ClientError(
      "Connect your own Anthropic API key to use AI repairs. Open “AI Keys”, paste a key that starts with sk-ant-, and try again.",
      400,
    );
    err.code = "anthropic_key_required";
    throw err;
  }
  return key;
}

/**
 * One-shot Anthropic Messages call over raw fetch (no SDK dependency added to
 * this lean service). Returns the concatenated text content. All provider
 * failures are translated into client-safe ClientErrors — a raw upstream error
 * is never surfaced to the user, and the key never appears in any message.
 */
export async function anthropicComplete(key, {
  model = "claude-opus-4-8",
  system,
  prompt,
  maxTokens = 1500,
  timeoutMs = 60000,
} = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        ...(system ? { system } : {}),
        messages: [{ role: "user", content: prompt }],
      }),
      signal: controller.signal,
    });
  } catch {
    const err = new ClientError("Couldn’t reach the AI service with your key. Check your connection and try again.", 502);
    err.code = "anthropic_unreachable";
    throw err;
  } finally {
    clearTimeout(timer);
  }

  if (res.status === 401 || res.status === 403) {
    const err = new ClientError("Your Anthropic API key was rejected. Check the key is correct and has available credit.", 400);
    err.code = "anthropic_key_invalid";
    throw err;
  }
  if (res.status === 429) {
    const err = new ClientError("Your Anthropic key hit a rate limit. Wait a moment and try the repair again.", 429);
    err.code = "anthropic_rate_limited";
    throw err;
  }
  if (!res.ok) {
    const err = new ClientError("The AI service returned an error for your key. Please try again shortly.", 502);
    err.code = "anthropic_error";
    throw err;
  }

  let data;
  try {
    data = await res.json();
  } catch {
    const err = new ClientError("The AI service returned an unreadable response. Please try again.", 502);
    err.code = "anthropic_error";
    throw err;
  }
  return (data.content || [])
    .filter((b) => b && b.type === "text")
    .map((b) => b.text)
    .join("");
}
