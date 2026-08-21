import type { ProviderType } from "./types";

export interface VerifyResult {
  valid: boolean;
  error?: string;
}

const VERIFY_TIMEOUT_MS = 15_000;

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), VERIFY_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function verifyAnthropic(apiKey: string): Promise<VerifyResult> {
  try {
    const res = await fetchWithTimeout("https://api.anthropic.com/v1/models", {
      method: "GET",
      headers: {
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
    });
    if (res.ok) return { valid: true };
    if (res.status === 401) return { valid: false, error: "Invalid API key" };
    return {
      valid: false,
      error: `Anthropic returned HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      valid: false,
      error:
        err instanceof DOMException && err.name === "AbortError"
          ? "Request timed out"
          : "Could not reach Anthropic API",
    };
  }
}

async function verifyOpenAI(apiKey: string): Promise<VerifyResult> {
  try {
    const res = await fetchWithTimeout("https://api.openai.com/v1/models", {
      method: "GET",
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    if (res.ok) return { valid: true };
    if (res.status === 401) return { valid: false, error: "Invalid API key" };
    return {
      valid: false,
      error: `OpenAI returned HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      valid: false,
      error:
        err instanceof DOMException && err.name === "AbortError"
          ? "Request timed out"
          : "Could not reach OpenAI API",
    };
  }
}

async function verifyGoogle(apiKey: string): Promise<VerifyResult> {
  try {
    const res = await fetchWithTimeout(
      `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(apiKey)}`,
      { method: "GET" },
    );
    if (res.ok) return { valid: true };
    if (res.status === 400 || res.status === 403)
      return { valid: false, error: "Invalid API key" };
    return {
      valid: false,
      error: `Google returned HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      valid: false,
      error:
        err instanceof DOMException && err.name === "AbortError"
          ? "Request timed out"
          : "Could not reach Google AI API",
    };
  }
}

async function verifyOpenRouter(apiKey: string): Promise<VerifyResult> {
  try {
    const res = await fetchWithTimeout(
      "https://openrouter.ai/api/v1/auth/key",
      {
        method: "GET",
        headers: { Authorization: `Bearer ${apiKey}` },
      },
    );
    if (res.ok) return { valid: true };
    if (res.status === 401 || res.status === 403)
      return { valid: false, error: "Invalid API key" };
    return {
      valid: false,
      error: `OpenRouter returned HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      valid: false,
      error:
        err instanceof DOMException && err.name === "AbortError"
          ? "Request timed out"
          : "Could not reach OpenRouter API",
    };
  }
}

async function verifyInception(apiKey: string): Promise<VerifyResult> {
  try {
    const res = await fetchWithTimeout(
      "https://api.inceptionlabs.ai/v1/models",
      {
        method: "GET",
        headers: { Authorization: `Bearer ${apiKey}` },
      },
    );
    if (res.ok) return { valid: true };
    if (res.status === 401 || res.status === 403)
      return { valid: false, error: "Invalid API key" };
    return {
      valid: false,
      error: `Inception returned HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      valid: false,
      error:
        err instanceof DOMException && err.name === "AbortError"
          ? "Request timed out"
          : "Could not reach Inception API",
    };
  }
}

/**
 * Verify an API key by making a lightweight request to the provider's API.
 * Providers without a simple verification endpoint (bedrock, local, pensar)
 * are skipped and treated as valid.
 */
export async function verifyApiKey(
  provider: ProviderType,
  apiKey: string,
): Promise<VerifyResult> {
  switch (provider) {
    case "anthropic":
      return verifyAnthropic(apiKey);
    case "openai":
      return verifyOpenAI(apiKey);
    case "google":
      return verifyGoogle(apiKey);
    case "openrouter":
      return verifyOpenRouter(apiKey);
    case "concentrate":
      return apiKey.startsWith("sk-cn")
        ? { valid: true }
        : {
            valid: false,
            error: "Concentrate API keys start with sk-cn",
          };
    case "inception":
      return verifyInception(apiKey);
    case "bedrock":
    case "local":
    case "pensar":
      return { valid: true };
    default:
      return { valid: true };
  }
}
