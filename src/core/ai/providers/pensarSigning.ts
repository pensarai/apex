import { createHmac, createHash, randomUUID } from "crypto";

/**
 * Sign an inference request for the Pensar Gateway.
 *
 * The signature proves possession of the server-issued signing key
 * and binds the request to a specific timestamp, nonce, model, and body —
 * preventing replay attacks and request tampering.
 *
 * Payload format: "<timestamp>\n<nonce>\n<modelId>\n<SHA256(body)>"
 */
export function signGatewayRequest(
  signingKey: string,
  modelId: string,
  body: string,
): { signature: string; timestamp: string; nonce: string } {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomUUID();
  const bodyHash = createHash("sha256").update(body).digest("hex");
  const payload = `${timestamp}\n${nonce}\n${modelId}\n${bodyHash}`;
  const signature = createHmac("sha256", signingKey)
    .update(payload)
    .digest("base64");
  return { signature, timestamp, nonce };
}
