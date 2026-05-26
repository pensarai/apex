import { z } from "zod";
import {
  type AIAuthConfig,
  type AIModel,
  generateObjectResponse,
} from "../core/ai";

// Random name generator (GitHub-style)
const adjectives = [
  "swift",
  "bright",
  "calm",
  "bold",
  "keen",
  "noble",
  "quick",
  "sharp",
  "vivid",
  "warm",
  "agile",
  "brave",
  "clever",
  "daring",
  "eager",
  "fierce",
  "gentle",
  "humble",
  "jolly",
  "lively",
  "merry",
  "nimble",
  "proud",
  "quiet",
  "rapid",
  "serene",
  "sturdy",
  "tender",
  "valiant",
  "witty",
  "zealous",
];

const nouns = [
  "falcon",
  "wolf",
  "hawk",
  "bear",
  "lion",
  "tiger",
  "eagle",
  "raven",
  "phoenix",
  "dragon",
  "panther",
  "cobra",
  "viper",
  "shark",
  "orca",
  "mantis",
  "spider",
  "scorpion",
  "hydra",
  "griffin",
  "sphinx",
  "kraken",
  "cipher",
  "nexus",
  "prism",
  "vector",
  "matrix",
  "pulse",
  "surge",
  "flux",
];

export function generateRandomName(): string {
  const adj =
    adjectives[Math.floor(Math.random() * adjectives.length)] ?? "swift";
  const noun = nouns[Math.floor(Math.random() * nouns.length)] ?? "falcon";
  return `${adj}-${noun}`;
}

const sessionNameSchema = z.object({
  name: z
    .string()
    .describe(
      "A short, descriptive session name (2-4 words, lowercase, hyphenated)",
    ),
});

/**
 * AI-generate a descriptive session name based on targets and/or user message.
 * Returns null on failure — callers should keep the placeholder name.
 */
export async function generateSessionName(opts: {
  targets: string[];
  userMessage?: string;
  model: AIModel;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
}): Promise<string | null> {
  const { targets, userMessage, model, authConfig, abortSignal } = opts;

  const contextParts: string[] = [];
  if (targets.length > 0) {
    contextParts.push(`Target(s): ${targets.join(", ")}`);
  }
  if (userMessage) {
    contextParts.push(`User objective: ${userMessage}`);
  }
  if (contextParts.length === 0) return null;

  const prompt = [
    "Generate a short, descriptive name for a penetration testing session.",
    "The name should be 2-4 lowercase words separated by hyphens.",
    "It should capture the key aspect of the target or task — e.g. 'acme-api-pentest', 'login-auth-bypass', 'ecommerce-checkout-test'.",
    "",
    ...contextParts,
  ].join("\n");

  try {
    const result = await generateObjectResponse({
      model,
      schema: sessionNameSchema,
      prompt,
      maxTokens: 50,
      temperature: 0.7,
      authConfig,
      abortSignal,
    });

    if (!result?.name) return null;

    const name = result.name
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 50);

    return name || null;
  } catch {
    return null;
  }
}
