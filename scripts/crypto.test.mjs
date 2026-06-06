// Proves the token-at-rest encryption (_crypto.js): AES-256-GCM round-trip,
// idempotent double-encrypt guard, passthrough of non-secrets, and that tampered
// or malformed ciphertext is rejected (GCM auth tag), plus the OAuth/connector
// state signing (signState/verifyState in _lib.js): valid/expired/tampered.
process.env.CODECANIC_SESSION_SECRET = "crypto-test-secret-0123456789abcdef";

import { encryptSecret, decryptSecret } from "../api/_crypto.js";
import { signState, verifyState } from "../api/_lib.js";

let pass = 0, fail = 0;
const failures = [];
function ok(name, cond, detail = "") {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(`${name}${detail ? ` — ${detail}` : ""}`); console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ""}`); }
}

console.log("Token-at-rest encryption (AES-256-GCM)");
{
  const secret = "ghp_aBcD1234567890_secretToken";
  const enc = encryptSecret(secret);
  ok("ciphertext carries the enc:v1: envelope", typeof enc === "string" && enc.startsWith("enc:v1:"));
  ok("ciphertext does not contain the plaintext", !enc.includes(secret));
  ok("round-trips back to the original", decryptSecret(enc) === secret);

  // Idempotence: encrypting an already-encrypted value is a no-op (no double wrap).
  ok("double-encrypt is a no-op", encryptSecret(enc) === enc);

  // Two encryptions of the same plaintext differ (random IV) but both decrypt.
  const enc2 = encryptSecret(secret);
  ok("random IV → distinct ciphertexts", enc !== enc2);
  ok("second ciphertext also round-trips", decryptSecret(enc2) === secret);

  // Passthrough: non-secrets and empties are returned unchanged.
  ok("null passthrough", encryptSecret(null) === null && decryptSecret(null) === null);
  ok("empty-string passthrough", encryptSecret("") === "");
  ok("plaintext (no envelope) decrypts to itself", decryptSecret("not-encrypted") === "not-encrypted");

  // Tamper: flipping a ciphertext byte must fail the GCM auth tag.
  const parts = enc.split(":");
  const ctBuf = Buffer.from(parts[3], "base64url");
  ctBuf[0] ^= 0x01;
  const tampered = [parts[0], parts[1], parts[2], ctBuf.toString("base64url"), parts[4]].join(":");
  let tamperThrew = false;
  try { decryptSecret(tampered); } catch { tamperThrew = true; }
  ok("tampered ciphertext is rejected (GCM auth tag)", tamperThrew);

  // Malformed envelope (wrong segment count) throws.
  let malformedThrew = false;
  try { decryptSecret("enc:v1:onlytwo"); } catch { malformedThrew = true; }
  ok("malformed envelope is rejected", malformedThrew);
}

console.log("\nState signing (signState / verifyState)");
{
  const payload = { userId: "u1", organizationId: "o1", provider: "GitHub", expiresAt: Date.now() + 60_000 };
  const token = signState(payload);
  const verified = verifyState(token);
  ok("valid state verifies and round-trips", verified?.userId === "u1" && verified?.provider === "GitHub");

  ok("garbage token is rejected", verifyState("not-a-token") === null);
  ok("empty token is rejected", verifyState("") === null);

  // Tampered signature is rejected.
  const [value] = token.split(".");
  ok("tampered signature is rejected", verifyState(`${value}.deadbeef`) === null);

  // Tampered payload (re-encoded) no longer matches the signature.
  const forged = Buffer.from(JSON.stringify({ ...payload, userId: "attacker" })).toString("base64url");
  ok("tampered payload is rejected", verifyState(`${forged}.${token.split(".")[1]}`) === null);

  // Expired state is rejected even with a valid signature.
  const expired = signState({ ...payload, expiresAt: Date.now() - 1000 });
  ok("expired state is rejected", verifyState(expired) === null);
}

console.log(`\n${"=".repeat(50)}\nRESULT: ${pass} passed, ${fail} failed`);
if (failures.length) { console.log("\nFAILURES:"); failures.forEach((f) => console.log(`  - ${f}`)); }
process.exit(fail > 0 ? 1 : 0);
