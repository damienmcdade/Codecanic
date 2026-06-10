// Pluggable transactional email for Codecanic.
//
// If RESEND_API_KEY is set, email is delivered via Resend. Otherwise the message
// is logged (dev) — and callers expose the token in API responses only when not
// production-like, so flows are testable without an email provider.
import { fetchWithTimeout } from "./_http.js";

const FROM = process.env.CODECANIC_EMAIL_FROM || "Codecanic <noreply@codecanic.app>";

export function emailConfigured() {
  return Boolean(process.env.RESEND_API_KEY);
}

export async function sendEmail({ to, subject, text, html }) {
  if (!emailConfigured()) {
    console.log(`[email:dev] to=${to} subject="${subject}"\n${text}`);
    return { delivered: false, dev: true };
  }
  const res = await fetchWithTimeout("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ from: FROM, to, subject, text, html: html || `<pre>${text}</pre>` })
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`Email delivery failed (${res.status}): ${body.slice(0, 200)}`);
  }
  return { delivered: true };
}

export function sendVerificationEmail(to, link) {
  return sendEmail({
    to,
    subject: "Verify your Codecanic email",
    text: `Welcome to Codecanic. Confirm your email address to start scanning:\n\n${link}\n\nThis link expires in 24 hours. If you didn't sign up, ignore this email.`
  });
}

export function sendPasswordResetEmail(to, link) {
  return sendEmail({
    to,
    subject: "Reset your Codecanic password",
    text: `We received a request to reset your Codecanic password.\n\n${link}\n\nThis link expires in 1 hour. If you didn't request this, ignore this email — your password is unchanged.`
  });
}
