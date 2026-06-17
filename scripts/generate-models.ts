/**
 * Build-time script that extracts model IDs from AI SDK provider packages'
 * TypeScript type definitions and generates the model list files.
 *
 * Run: bun run generate:models
 *
 * When you bump an AI SDK package version, re-run this script to pick up
 * any newly added models automatically.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const MODELS_DIR = resolve(ROOT, "src/core/ai/models");

// ---------------------------------------------------------------------------
// 1. Parse union-type string literals from .d.ts files
// ---------------------------------------------------------------------------

function extractUnionMembers(dtsPath: string, typeName: string): string[] {
  const content = readFileSync(dtsPath, "utf-8");
  const typeRegex = new RegExp(`type\\s+${typeName}\\s*=\\s*([^;]+)`, "s");
  const match = content.match(typeRegex);
  if (!match?.[1]) {
    throw new Error(`Could not find type ${typeName} in ${dtsPath}`);
  }

  const unionBody = match[1];
  const members: string[] = [];
  const literalRegex = /'([^']+)'/g;
  for (
    let m = literalRegex.exec(unionBody);
    m !== null;
    m = literalRegex.exec(unionBody)
  ) {
    if (m[1]) members.push(m[1]);
  }
  return members;
}

// ---------------------------------------------------------------------------
// 2. Context-length lookup
// ---------------------------------------------------------------------------

const CONTEXT_LENGTHS: Record<string, number> = {
  // Anthropic – all Claude 3+ have 200k, older have 100k
  "claude-3": 200000,
  "claude-haiku-4": 200000,
  "claude-sonnet-4": 200000,
  "claude-opus-4": 200000,
  "claude-opus-4-7": 1000000,
  "claude-opus-4-8": 1000000,
  "claude-2": 100000,
  "claude-instant": 100000,

  // OpenAI
  "gpt-5.5": 1050000,
  "gpt-5": 200000,
  "gpt-4.5": 128000,
  "gpt-4.1": 128000,
  "gpt-4o": 128000,
  "gpt-4-turbo": 128000,
  "gpt-4-0613": 8192,
  "gpt-4": 8192,
  "gpt-3.5-turbo": 16385,
  "chatgpt-4o": 128000,
  o1: 200000,
  o3: 200000,
  "o3-mini": 128000,
  o4: 200000,

  // Google Gemini
  "gemini-2.0": 1000000,
  "gemini-2.5": 1000000,
  "gemini-3": 1000000,
  "gemini-3.1": 1000000,
  "gemini-pro": 1000000,
  "gemini-flash": 1000000,
  "gemma-3": 8192,

  // Bedrock provider-specific
  "amazon.titan-tg1": 8000,
  "amazon.titan-text-express": 8000,
  "amazon.titan-text-lite": 4000,
  "amazon.titan-text-premier": 32000,
  "amazon.nova-micro": 128000,
  "amazon.nova-lite": 300000,
  "amazon.nova-pro": 300000,
  "amazon.nova-premier": 300000,
  "cohere.command-text": 4000,
  "cohere.command-light": 4000,
  "cohere.command-r": 128000,
  "meta.llama3-8b": 8000,
  "meta.llama3-70b": 8000,
  "meta.llama3-1": 128000,
  "meta.llama3-2": 128000,
  "meta.llama3-3": 128000,
  "meta.llama4": 128000,
  "mistral.mistral-7b": 32000,
  "mistral.mixtral": 32000,
  "mistral.mistral-small": 32000,
  "mistral.mistral-large": 128000,
  "mistral.pixtral": 128000,
  "openai.gpt-oss": 8000,
  "deepseek.r1": 64000,
  "moonshotai.kimi": 262000,
  "anthropic.claude-v2": 100000,
  "anthropic.claude-instant": 100000,
  "anthropic.claude-3": 200000,
  "anthropic.claude-haiku": 200000,
  "anthropic.claude-sonnet": 200000,
  "anthropic.claude-opus": 200000,
  "anthropic.claude-opus-4-7": 1000000,
  "anthropic.claude-opus-4-8": 1000000,
};

function getContextLength(modelId: string): number | undefined {
  // Strip regional prefixes for lookup
  const bare = modelId
    .replace(/^(us\.|global\.|eu\.)/, "")
    .replace(
      /^(anthropic\.|amazon\.|meta\.|cohere\.|mistral\.|openai\.|deepseek\.)/,
      (m) => m,
    );

  // Try progressively shorter prefixes
  const parts = bare.split("-");
  for (let i = parts.length; i > 0; i--) {
    const prefix = parts.slice(0, i).join("-");
    if (CONTEXT_LENGTHS[prefix] !== undefined) {
      return CONTEXT_LENGTHS[prefix];
    }
  }

  // Try with dot-separated segments (for bedrock IDs like amazon.titan-text-express-v1)
  for (const [key, value] of Object.entries(CONTEXT_LENGTHS)) {
    if (bare.startsWith(key)) {
      return value;
    }
  }

  return undefined;
}

// Append IDs from `extras` that aren't already present in `target`.
function appendMissing<T>(target: T[], extras: readonly T[]): void {
  const seen = new Set(target);
  for (const id of extras) {
    if (!seen.has(id)) target.push(id);
  }
}

// Higher score = newer. Score reflects model family generation, not release
// date — base, dated, and variant IDs in the same family share a score so a
// stable sort keeps the SDK's intra-family ordering intact.
function openaiVersionScore(id: string): number {
  const gpt = id.match(/^gpt-(\d+)(?:\.(\d+))?/);
  if (gpt?.[1]) {
    const major = parseInt(gpt[1], 10);
    const minor = gpt[2] ? parseInt(gpt[2], 10) : 0;
    // major*1000 leaves room for minor versions ≥10 (gpt-5.10 won't collide
    // with gpt-6.0). Pro variants edge out non-pro siblings within a generation.
    const pro = /-pro(?:-|$)/.test(id) ? 5 : 0;
    return 5000 + major * 1000 + minor * 10 + pro;
  }
  const o = id.match(/^o(\d+)(?:-|$)/);
  if (o?.[1]) {
    return 4000 + parseInt(o[1], 10) * 100;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// 3. Human-readable display name generation
// ---------------------------------------------------------------------------

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function formatModelName(modelId: string, provider: string): string {
  let id = modelId;

  // --- Bedrock: strip regional + vendor prefix, track suffix ---
  let regionSuffix = "";
  if (provider === "bedrock") {
    if (id.startsWith("us.")) {
      regionSuffix = " (US)";
      id = id.slice(3);
    } else if (id.startsWith("global.")) {
      regionSuffix = " (Global)";
      id = id.slice(7);
    } else if (id.startsWith("eu.")) {
      regionSuffix = " (EU)";
      id = id.slice(3);
    }

    // Strip vendor prefix but keep vendor label for non-anthropic
    const vendors: [string, string][] = [
      ["anthropic.", ""],
      ["amazon.", "Amazon "],
      ["meta.", ""],
      ["cohere.", "Cohere "],
      ["mistral.", ""],
      ["openai.", ""],
      ["deepseek.", "DeepSeek "],
      ["moonshotai.", "Moonshot AI "],
    ];
    for (const [prefix, label] of vendors) {
      if (id.startsWith(prefix)) {
        id = label + id.slice(prefix.length);
        break;
      }
    }
  }

  // Extract trailing date + Bedrock version suffix:
  // e.g. "-20241022-v1:0" → date "(2024-10-22)", strip "-v1:0"
  // But keep "-v2:1" when it's the model version (e.g. claude-v2:1)
  let dateSuffix = "";

  // First try: date followed by version suffix (-v1:0 or -v1)
  const dateVersionMatch = id.match(
    /^(.*)-(\d{4})(\d{2})(\d{2})-v\d+(?::\d+)?$/,
  );
  if (dateVersionMatch?.[1]) {
    id = dateVersionMatch[1];
    dateSuffix = ` (${dateVersionMatch[2]}-${dateVersionMatch[3]}-${dateVersionMatch[4]})`;
  } else {
    // Try: just a date suffix (no version)
    id = id.replace(/-(\d{4})(\d{2})(\d{2})$/, (_, y, m, d) => {
      dateSuffix = ` (${y}-${m}-${d})`;
      return "";
    });

    // Try: standalone Bedrock infrastructure version suffix (-v1:0 or -v1)
    // Don't strip if it's the model version (claude-v2, claude-v2:1, instant-v1)
    const isModelVersion = /claude-v\d|instant-v\d/.test(id);
    if (!isModelVersion) {
      if (dateSuffix) {
        id = id.replace(/-v\d+(?::\d+)?$/, "");
      } else {
        id = id.replace(/-v\d+:\d+$/, "");
        // Also strip bare -v\d+ suffix when NOT a model version
        // (e.g., claude-opus-4-6-v1 → claude-opus-4-6)
        id = id.replace(/-v\d+$/, (match) => {
          // Only strip if preceded by a model family pattern, not "claude-v2"
          if (/\d-v\d+$/.test(id)) return "";
          return match;
        });
      }
    }
  }

  // Handle "-latest" suffix
  if (id.endsWith("-latest")) {
    id = id.replace(/-latest$/, "");
    dateSuffix = " (Latest)";
  }

  // Handle "-chat-latest" suffix
  if (id.endsWith("-chat-latest")) {
    id = id.replace(/-chat-latest$/, "");
    dateSuffix = " Chat (Latest)";
  }

  // Handle "-preview" suffix
  if (id.endsWith("-preview")) {
    id = id.replace(/-preview$/, "");
    dateSuffix = ` Preview${dateSuffix}`;
  }

  // --- Claude models ---
  const claudeMatch = id.match(/^Claude\s+(.+)$|^claude-(.+)$/);
  if (claudeMatch) {
    const rest = claudeMatch[1] || claudeMatch[2];
    if (!rest) return id + dateSuffix;
    // Parse Claude model families: "3-5-haiku", "opus-4-1", "sonnet-4-5", etc.
    const familyPatterns: [RegExp, (m: RegExpMatchArray) => string][] = [
      // claude-3-5-haiku → Claude 3.5 Haiku
      [
        /^(\d+)-(\d+)-(\w+)$/,
        (m) => m[1] && m[2] && m[3] ? `Claude ${m[1]}.${m[2]} ${capitalize(m[3])}` : rest,
      ],
      // claude-3-haiku → Claude 3 Haiku
      [/^(\d+)-(\w+)$/, (m) => m[1] && m[2] ? `Claude ${m[1]} ${capitalize(m[2])}` : rest],
      // claude-haiku-4-5 → Claude Haiku 4.5
      [
        /^(\w+)-(\d+)-(\d+)$/,
        (m) => m[1] && m[2] && m[3] ? `Claude ${capitalize(m[1])} ${m[2]}.${m[3]}` : rest,
      ],
      // claude-haiku-4 → Claude Haiku 4
      [/^(\w+)-(\d+)$/, (m) => m[1] && m[2] ? `Claude ${capitalize(m[1])} ${m[2]}` : rest],
      // claude-v2 → Claude v2
      [/^v(\d+)$/, (m) => `Claude v${m[1]}`],
      // claude-instant-v1 → Claude Instant v1
      [/^instant-v(\d+)$/, (m) => `Claude Instant v${m[1]}`],
      // Fallback
      [/^(.+)$/, (m) => `Claude ${m[1]}`],
    ];
    for (const [pattern, formatter] of familyPatterns) {
      const m = rest.match(pattern);
      if (m) {
        const name = formatter(m) + dateSuffix;
        return provider === "bedrock"
          ? name + (regionSuffix || " (Bedrock)")
          : name;
      }
    }
  }

  // --- GPT models ---
  if (id.startsWith("gpt-") || id.startsWith("GPT-")) {
    const name = `GPT-${id.replace(/^gpt-/i, "")}${dateSuffix}`;
    return provider === "bedrock"
      ? name + (regionSuffix || " (Bedrock)")
      : name;
  }
  if (id.startsWith("chatgpt-") || id.startsWith("ChatGPT-")) {
    const name = `ChatGPT-${id.replace(/^chatgpt-/i, "")}${dateSuffix}`;
    return provider === "bedrock"
      ? name + (regionSuffix || " (Bedrock)")
      : name;
  }

  // --- O-series (o1, o3, o3-mini, o4-mini) ---
  if (/^o\d/.test(id)) {
    const name = id.toUpperCase().replace(/-MINI/, " Mini") + dateSuffix;
    return provider === "bedrock"
      ? name + (regionSuffix || " (Bedrock)")
      : name;
  }

  // --- Llama models ---
  const llamaMatch = id.match(/^llama(\d+)-?(.*)$/i);
  if (llamaMatch?.[1]) {
    const majorVersion = llamaMatch[1];
    let rest = llamaMatch[2] || "";
    rest = rest.replace(/-instruct$/, "");

    // Parse sub-version: "1-70b" → ".1 70B", "2-11b" → ".2 11B"
    let subVersion = "";
    rest = rest.replace(/^(\d+)-/, (_, sv) => {
      subVersion = `.${sv}`;
      return "";
    });

    // Remaining parts (model name tokens like "scout-17b", "maverick-17b")
    const parts = rest.split("-").filter(Boolean);
    const formatted = parts.map((p) => {
      if (/^\d+b$/i.test(p)) return p.replace(/b$/i, "B");
      return capitalize(p);
    });

    const name = `Llama ${majorVersion}${subVersion}${formatted.length ? ` ${formatted.join(" ")}` : ""} Instruct${dateSuffix}`;
    return provider === "bedrock"
      ? name + (regionSuffix || " (Bedrock)")
      : name;
  }

  // --- Amazon models ---
  if (id.startsWith("Amazon ")) {
    let rest = id.slice("Amazon ".length);
    // titan-tg1-large → Titan TG1 Large
    // nova-micro → Nova Micro, nova-pro → Nova Pro
    const knownAcronyms = new Set(["tg1", "v1", "v2"]);
    rest = rest
      .split("-")
      .map((part) => {
        if (/^\d/.test(part) || /^v\d/.test(part)) return part;
        if (knownAcronyms.has(part)) return part.toUpperCase();
        return capitalize(part);
      })
      .join(" ");
    const name = `Amazon ${rest}${dateSuffix}`;
    return name + (regionSuffix || " (Bedrock)");
  }

  // --- Cohere models ---
  if (id.startsWith("Cohere ")) {
    let rest = id.slice("Cohere ".length);
    rest = rest.replace(/-/g, " ").split(" ").map(capitalize).join(" ");
    const name = `Cohere ${rest}${dateSuffix}`;
    return name + (regionSuffix || " (Bedrock)");
  }

  // --- Mistral/Mixtral/Pixtral ---
  const mistralMatch = id.match(/^(mistral|mixtral|pixtral)-(.+)$/i);
  if (mistralMatch?.[1] && mistralMatch[2]) {
    const brand = capitalize(mistralMatch[1]);
    let rest = mistralMatch[2];
    // 7b-instruct → 7B Instruct
    rest = rest
      .replace(/-instruct$/, " Instruct")
      .replace(/(\d+)b\b/gi, (_, n) => `${n}B`)
      .replace(/(\d+)x(\d+)b/gi, (_, a, b) => `${a}x${b}B`);
    const name = `${brand} ${capitalize(rest)}${dateSuffix}`;
    return provider === "bedrock"
      ? name + (regionSuffix || " (Bedrock)")
      : name;
  }

  // --- DeepSeek ---
  if (id.startsWith("DeepSeek ")) {
    let rest = id.slice("DeepSeek ".length);
    rest = capitalize(rest);
    const name = `DeepSeek ${rest}${dateSuffix}`;
    return provider === "bedrock"
      ? name + (regionSuffix || " (Bedrock)")
      : name;
  }

  // --- Moonshot AI (Kimi) models ---
  if (id.startsWith("Moonshot AI ")) {
    let rest = id.slice("Moonshot AI ".length);
    rest = rest
      .split("-")
      .map((p) => {
        if (/^k\d/i.test(p)) return p.toUpperCase();
        return capitalize(p);
      })
      .join(" ");
    const name = `Moonshot AI ${rest}${dateSuffix}`;
    return name + (regionSuffix || " (Bedrock)");
  }

  // --- Google Gemini/Gemma models ---
  if (id.startsWith("gemini-") || id.startsWith("gemma-")) {
    const parts = id.split("-");
    let name = "";
    if (parts[0] === "gemini") {
      name = "Gemini";
      const rest = parts.slice(1);
      if (rest.length > 0 && rest[0]) {
        const version = rest[0];
        name += ` ${version}`;
        const remaining = rest.slice(1);
        if (remaining.length > 0) {
          name +=
            " " +
            remaining
              .map((p) => {
                if (p === "pro") return "Pro";
                if (p === "flash") return "Flash";
                if (p === "lite") return "Lite";
                if (p === "exp") return "Experimental";
                if (p === "preview") return "Preview";
                if (p === "latest") return "Latest";
                if (p === "image") return "Image";
                if (p === "native") return "Native";
                if (p === "audio") return "Audio";
                if (p === "tts") return "TTS";
                if (p === "customtools") return "Custom Tools";
                return capitalize(p);
              })
              .join(" ");
        }
      }
    } else if (parts[0] === "gemma") {
      name = "Gemma";
      const rest = parts.slice(1);
      if (rest.length > 0) {
        name +=
          " " +
          rest
            .map((p) => {
              if (p === "it") return "Instruct";
              if (/^\d+b$/.test(p)) return p.replace("b", "B");
              return p;
            })
            .join(" ");
      }
    }
    return name + dateSuffix;
  }

  // --- Fallback ---
  const name = id + dateSuffix;
  if (provider === "bedrock") {
    return name + (regionSuffix || " (Bedrock)");
  }
  return name;
}

// ---------------------------------------------------------------------------
// 4. Bedrock regional variant generation
// ---------------------------------------------------------------------------

const BEDROCK_GLOBAL_PREFIXES = ["anthropic."];

function generateBedrockRegionalVariants(allIds: string[]): string[] {
  const existing = new Set(allIds);
  const regional: string[] = [];

  // Only generate global.* variants for base (non-prefixed) Anthropic models
  for (const id of allIds) {
    if (
      id.startsWith("us.") ||
      id.startsWith("global.") ||
      id.startsWith("eu.")
    ) {
      continue;
    }
    if (BEDROCK_GLOBAL_PREFIXES.some((p) => id.startsWith(p))) {
      const globalId = `global.${id}`;
      if (!existing.has(globalId)) {
        regional.push(globalId);
      }
    }
  }
  return regional;
}

// ---------------------------------------------------------------------------
// 5. Code generation
// ---------------------------------------------------------------------------

interface ModelEntry {
  id: string;
  name: string;
  provider: string;
  contextLength?: number;
}

function generateFileContent(models: ModelEntry[], exportName: string): string {
  const lines = [
    "// Auto-generated by scripts/generate-models.ts — do not edit manually.",
    `// Re-generate: bun run generate:models`,
    "",
    `import type { ModelInfo } from "../ai";`,
    "",
    `export const ${exportName}: ModelInfo[] = [`,
  ];

  for (const m of models) {
    const ctxLine =
      m.contextLength !== undefined
        ? `\n    contextLength: ${m.contextLength},`
        : "";
    lines.push(`  {
    id: ${JSON.stringify(m.id)},
    name: ${JSON.stringify(m.name)},
    provider: ${JSON.stringify(m.provider)},${ctxLine}
  },`);
  }

  lines.push("];", "");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// 6. Model ID filters — exclude non-chat models
// ---------------------------------------------------------------------------

const EXCLUDED_PATTERNS = [
  /audio/i,
  /search/i,
  /transcri/i,
  /speech/i,
  /tts/i,
  /whisper/i,
  /image/i,
  /dall-e/i,
  /embed/i,
];

function isRelevantChatModel(id: string): boolean {
  return !EXCLUDED_PATTERNS.some((re) => re.test(id));
}

// ---------------------------------------------------------------------------
// 7. Main
// ---------------------------------------------------------------------------

function main() {
  // ---- Anthropic ----
  const anthropicDts = resolve(
    ROOT,
    "node_modules/@ai-sdk/anthropic/dist/internal/index.d.ts",
  );
  const anthropicIds = extractUnionMembers(
    anthropicDts,
    "AnthropicMessagesModelId",
  );

  // Models available on the Anthropic API but not yet in the AI SDK type definitions
  appendMissing(anthropicIds, ["claude-opus-4-7", "claude-opus-4-8"]);

  const anthropicModels: ModelEntry[] = anthropicIds.map((id) => ({
    id,
    name: formatModelName(id, "anthropic"),
    provider: "anthropic",
    contextLength: getContextLength(id),
  }));

  // ---- OpenAI ----
  const openaiDts = resolve(
    ROOT,
    "node_modules/@ai-sdk/openai/dist/internal/index.d.ts",
  );
  const openaiIds = extractUnionMembers(
    openaiDts,
    "OpenAIResponsesModelId",
  ).filter(isRelevantChatModel);

  // Models available on the OpenAI API but not yet in the AI SDK type definitions
  appendMissing(openaiIds, ["gpt-5.5", "gpt-5.5-2026-04-23"]);

  // OpenAI's SDK lists generations oldest-first; flip so the picker shows the
  // newest family first. Stable sort preserves intra-family declaration order.
  openaiIds.sort((a, b) => openaiVersionScore(b) - openaiVersionScore(a));

  const openaiModels: ModelEntry[] = openaiIds.map((id) => ({
    id,
    name: formatModelName(id, "openai"),
    provider: "openai",
    contextLength: getContextLength(id),
  }));

  // ---- Google ----
  const googleDts = resolve(
    ROOT,
    "node_modules/@ai-sdk/google/dist/internal/index.d.ts",
  );
  const googleIds = extractUnionMembers(
    googleDts,
    "GoogleGenerativeAIModelId",
  ).filter(isRelevantChatModel);
  const googleModels: ModelEntry[] = googleIds.map((id) => ({
    id,
    name: formatModelName(id, "google"),
    provider: "google",
    contextLength: getContextLength(id),
  }));

  // ---- Bedrock ----
  const bedrockDts = resolve(
    ROOT,
    "node_modules/@ai-sdk/amazon-bedrock/dist/index.d.ts",
  );
  const bedrockRawIds = extractUnionMembers(bedrockDts, "BedrockChatModelId");
  // Deduplicate (SDK type has some duplicates)
  const bedrockBaseIds = [...new Set(bedrockRawIds)];

  // Models available on Bedrock but not yet in the AI SDK type definitions
  appendMissing(bedrockBaseIds, [
    "moonshotai.kimi-k2.5",
    "anthropic.claude-opus-4-7",
    "anthropic.claude-opus-4-8",
    "us.anthropic.claude-opus-4-8",
  ]);

  const bedrockRegionalIds = generateBedrockRegionalVariants(bedrockBaseIds);
  const allBedrockIds = [...bedrockBaseIds, ...bedrockRegionalIds];
  const bedrockModels: ModelEntry[] = allBedrockIds.map((id) => ({
    id,
    name: formatModelName(id, "bedrock"),
    provider: "bedrock",
    contextLength: getContextLength(id),
  }));

  // ---- Write files ----
  writeFileSync(
    resolve(MODELS_DIR, "anthropic.ts"),
    generateFileContent(anthropicModels, "ANTHROPIC_MODELS"),
  );
  console.log(`✓ anthropic.ts — ${anthropicModels.length} models`);

  writeFileSync(
    resolve(MODELS_DIR, "openai.ts"),
    generateFileContent(openaiModels, "OPENAI_MODELS"),
  );
  console.log(`✓ openai.ts — ${openaiModels.length} models`);

  writeFileSync(
    resolve(MODELS_DIR, "google.ts"),
    generateFileContent(googleModels, "GOOGLE_MODELS"),
  );
  console.log(`✓ google.ts — ${googleModels.length} models`);

  writeFileSync(
    resolve(MODELS_DIR, "bedrock.ts"),
    generateFileContent(bedrockModels, "BEDROCK_MODELS"),
  );
  console.log(`✓ bedrock.ts — ${bedrockModels.length} models`);

  console.log("\nOpenRouter models are curated manually in openrouter.ts.");
  console.log("Local models are user-defined at runtime.\n");
}

main();
