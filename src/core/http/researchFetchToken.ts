import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const TOKEN_PREFIX = "apex-research-v1";
const TOKEN_TTL_MS = 10 * 60 * 1000;
const signingKey = randomBytes(32);

function normalizedUrl(url: string): string {
  const parsed = new URL(url);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported research URL protocol: ${parsed.protocol}`);
  }
  return parsed.toString();
}

function signature(payload: string): string {
  return createHmac("sha256", signingKey).update(payload).digest("base64url");
}

export function createLocalResearchFetchToken(
  url: string,
  now = Date.now(),
): string {
  const payload = Buffer.from(
    JSON.stringify({
      url: normalizedUrl(url),
      expiresAt: now + TOKEN_TTL_MS,
    }),
  ).toString("base64url");
  return `${TOKEN_PREFIX}.${payload}.${signature(payload)}`;
}

export function verifyLocalResearchFetchToken(
  token: string,
  url: string,
  now = Date.now(),
): boolean {
  const [prefix, payload, candidate] = token.split(".");
  if (prefix !== TOKEN_PREFIX || !payload || !candidate) return false;

  const expected = signature(payload);
  const expectedBytes = Buffer.from(expected);
  const candidateBytes = Buffer.from(candidate);
  if (
    expectedBytes.length !== candidateBytes.length ||
    !timingSafeEqual(expectedBytes, candidateBytes)
  ) {
    return false;
  }

  try {
    const parsed = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    ) as { url?: unknown; expiresAt?: unknown };
    return (
      parsed.url === normalizedUrl(url) &&
      typeof parsed.expiresAt === "number" &&
      Number.isFinite(parsed.expiresAt) &&
      parsed.expiresAt >= now
    );
  } catch {
    return false;
  }
}
