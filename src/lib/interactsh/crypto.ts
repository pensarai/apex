// ---------------------------------------------------------------------------
// Crypto helpers for the interactsh protocol
//
// Uses Node.js `crypto` (supported by Bun) -- no external dependencies.
// ---------------------------------------------------------------------------

import {
  generateKeyPairSync,
  privateDecrypt,
  createDecipheriv,
  randomBytes,
  constants,
} from "crypto";

import { CORRELATION_CHARSET } from "./types";

// ---------------------------------------------------------------------------
// RSA key generation
// ---------------------------------------------------------------------------

export interface KeyPair {
  publicKey: string; // PEM
  privateKey: string; // PEM
  publicKeyDer: Buffer; // DER (PKIX / spki) for base64 registration
}

/**
 * Generate an RSA keypair suitable for interactsh registration.
 *
 * Returns PEM strings for internal use and the DER-encoded public key
 * (SPKI format) that the interactsh server expects as base64.
 */
export function generateRsaKeyPair(bits: number = 2048): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: bits,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  // Extract DER from PEM for the registration payload
  const derB64 = publicKey
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s/g, "");

  const publicKeyDer = Buffer.from(derB64, "base64");

  return { publicKey, privateKey, publicKeyDer };
}

// ---------------------------------------------------------------------------
// RSA-OAEP decryption (for the AES key in poll responses)
// ---------------------------------------------------------------------------

/**
 * Decrypt an RSA-OAEP encrypted buffer using the given private key.
 * interactsh uses SHA-256 as the OAEP hash.
 */
export function rsaDecrypt(
  encryptedData: Buffer,
  privateKeyPem: string,
): Buffer {
  return privateDecrypt(
    {
      key: privateKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedData,
  );
}

// ---------------------------------------------------------------------------
// AES-256-CFB decryption (for interaction data in poll responses)
// ---------------------------------------------------------------------------

/**
 * Decrypt AES-256-CFB encrypted data.
 *
 * The ciphertext format from interactsh is: IV (16 bytes) || ciphertext.
 */
export function aesDecrypt(data: Buffer, key: Buffer): Buffer {
  const iv = data.subarray(0, 16);
  const ciphertext = data.subarray(16);
  const decipher = createDecipheriv("aes-256-cfb", key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ---------------------------------------------------------------------------
// Random generation helpers
// ---------------------------------------------------------------------------

/** Generate a random correlation ID from the interactsh charset. */
export function generateCorrelationId(length: number = 20): string {
  const bytes = randomBytes(length);
  let id = "";
  for (let i = 0; i < length; i++) {
    id += CORRELATION_CHARSET[bytes[i]! % CORRELATION_CHARSET.length];
  }
  return id;
}

/** Generate a random secret key (hex string). */
export function generateSecretKey(): string {
  return randomBytes(16).toString("hex");
}
