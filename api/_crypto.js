import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";

let cachedKey = null;

function deriveKey() {
  if (cachedKey) return cachedKey;
  const secret = process.env.CODECANIC_SESSION_SECRET;
  if (!secret || secret.length < 16) {
    throw new Error("Cannot derive encryption key: CODECANIC_SESSION_SECRET is missing or too short.");
  }
  cachedKey = scryptSync(secret, "codecanic-token-kdf-v1", 32);
  return cachedKey;
}

export function encryptSecret(plaintext) {
  if (plaintext == null || plaintext === "") return plaintext;
  if (typeof plaintext !== "string") return plaintext;
  if (plaintext.startsWith("enc:v1:")) return plaintext;
  const key = deriveKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `enc:v1:${iv.toString("base64url")}:${ciphertext.toString("base64url")}:${authTag.toString("base64url")}`;
}

export function decryptSecret(value) {
  if (value == null || value === "") return value;
  if (typeof value !== "string") return value;
  if (!value.startsWith("enc:v1:")) return value;
  const parts = value.split(":");
  if (parts.length !== 5) throw new Error("Malformed encrypted secret.");
  const [, , ivB64, ctB64, tagB64] = parts;
  const key = deriveKey();
  const iv = Buffer.from(ivB64, "base64url");
  const ciphertext = Buffer.from(ctB64, "base64url");
  const tag = Buffer.from(tagB64, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}
