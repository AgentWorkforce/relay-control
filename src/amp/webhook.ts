import { createHmac, timingSafeEqual } from "node:crypto";

// Standard Webhooks (https://www.standardwebhooks.com), the scheme Relaycast
// signs subscription deliveries with:
//   webhook-signature: v1,<base64 HMAC-SHA256(secret bytes, "<id>.<ts>.<body>")>
// Several space-separated signatures are accepted during secret rotation.

const SECRET_PREFIX = "whsec_";
export const WEBHOOK_TOLERANCE_SECONDS = 5 * 60;

/** Raw key bytes of a `whsec_<base64>` secret; throws on malformed input. */
export function webhookSecretBytes(secret: string): Buffer {
  if (!secret.startsWith(SECRET_PREFIX)) throw new Error("Webhook secret must start with whsec_.");
  const encoded = secret.slice(SECRET_PREFIX.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error("Webhook secret must be base64.");
  return Buffer.from(encoded, "base64");
}

function digest(secret: string, id: string, ts: number, body: string): Buffer {
  return createHmac("sha256", webhookSecretBytes(secret)).update(`${id}.${ts}.${body}`).digest();
}

export function signWebhook(secret: string, id: string, ts: number, body: string): string {
  return `v1,${digest(secret, id, ts, body).toString("base64")}`;
}

export function verifyWebhook(
  secret: string,
  headers: { id: string | null; timestamp: string | null; signature: string | null },
  body: string,
  nowSeconds: number,
  toleranceSeconds = WEBHOOK_TOLERANCE_SECONDS,
): boolean {
  const { id, timestamp, signature } = headers;
  if (!id || id.length > 256 || !timestamp || !signature || !/^\d{1,12}$/.test(timestamp)) return false;
  const ts = Number(timestamp);
  if (Math.abs(nowSeconds - ts) > toleranceSeconds) return false;
  const expected = digest(secret, id, ts, body);
  return signature.split(" ").some((candidate) => {
    const [version, value] = candidate.split(",", 2);
    if (version !== "v1" || !value) return false;
    const actual = Buffer.from(value, "base64");
    return actual.byteLength === expected.byteLength && timingSafeEqual(actual, expected);
  });
}
