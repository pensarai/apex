import type {
  PromptInjectionCatalogEntry,
  PromptInjectionLibrary,
} from "../../prompt-injections";
import type {
  AgentRedTeamGoal,
  AgentRedTeamImpact,
  AgentRedTeamMutationId,
  AgentRedTeamSeed,
  AgentRedTeamSurface,
  AgentRedTeamTechniqueId,
  AgentRedTeamVector,
} from "../types";

export interface AgentRedTeamSeedAttemptInput {
  vector: AgentRedTeamVector;
  surface: AgentRedTeamSurface;
  impact: AgentRedTeamImpact;
  techniqueId: AgentRedTeamTechniqueId;
  mutationChain: AgentRedTeamMutationId[];
  carrierLabel: string;
  renderedPrompt: string;
  goal: AgentRedTeamGoal;
  seed: AgentRedTeamSeed;
}

export interface PromptInjectionLibrarySeedOptions {
  categories?: string[];
  tags?: string[];
  maxSeeds?: number;
}

function textFor(entry: PromptInjectionCatalogEntry): string {
  return [
    entry.id,
    entry.name,
    entry.category,
    entry.description,
    entry.expectedObservation,
    ...entry.tags,
    ...entry.deliveryHints,
  ]
    .join(" ")
    .toLowerCase();
}

function classifyEntry(entry: PromptInjectionCatalogEntry): {
  vector: AgentRedTeamVector;
  surface: AgentRedTeamSurface;
  impact: AgentRedTeamImpact;
  techniqueId: AgentRedTeamTechniqueId;
} {
  const text = textFor(entry);

  if (/\b(mcp|schema|tool[-\s]?description|registry)\b/.test(text)) {
    return {
      vector: "mcp-tool-registry-poisoning",
      surface: "mcp-server-metadata",
      impact: "tool-routing-hijack",
      techniqueId: "tool-surface-indirect",
    };
  }

  if (/\b(tool|function|browser|click|command|action)\b/.test(text)) {
    return {
      vector: "tool-output-injection",
      surface: "tool-return-value",
      impact: "unauthorized-tool-invocation",
      techniqueId: "tool-surface-indirect",
    };
  }

  if (/\b(exfil|secret|token|credential|tenant|workspace|data)\b/.test(text)) {
    return {
      vector: "indirect-prompt-injection",
      surface: "rag-corpus",
      impact: "cross-tenant-data-exfiltration",
      techniqueId: "stacked-composition",
    };
  }

  if (/\b(encode|encoding|unicode|stego|obfuscat|base64|hex)\b/.test(text)) {
    return {
      vector: "encoding-unicode-stego-bypass",
      surface: "chat-input",
      impact: "policy-refusal-bypass",
      techniqueId: "encoding-obfuscation",
    };
  }

  if (/\b(system|developer|role|authority|persona)\b/.test(text)) {
    return {
      vector: "direct-prompt-injection",
      surface: "chat-input",
      impact: "system-developer-prompt-disclosure",
      techniqueId: "authority-system-spoof",
    };
  }

  return {
    vector: "direct-prompt-injection",
    surface: "chat-input",
    impact: "policy-refusal-bypass",
    techniqueId: "stacked-composition",
  };
}

function seedGoal(entry: PromptInjectionCatalogEntry): AgentRedTeamGoal {
  return {
    id: `prompt-injection-library:${entry.id}`,
    description:
      entry.expectedObservation ||
      entry.description ||
      `Replay prompt-injection library seed ${entry.id} without exposing raw payload text`,
    impact: classifyEntry(entry).impact,
  };
}

function renderSeedReference(entry: PromptInjectionCatalogEntry): string {
  return [
    "Prompt-injection library seed reference.",
    "Resolve and deliver this only through Apex tools that support PromptInjectionRef.",
    `PromptInjectionRef: {"kind":"prompt_injection_ref","id":"${entry.id}"}`,
    `Payload hash: ${entry.payloadHash}`,
    `Category: ${entry.category}`,
    entry.tags.length > 0 ? `Tags: ${entry.tags.join(", ")}` : undefined,
    entry.deliveryHints.length > 0
      ? `Delivery hints: ${entry.deliveryHints.join(", ")}`
      : undefined,
    entry.expectedObservation
      ? `Expected observation: ${entry.expectedObservation}`
      : undefined,
  ]
    .filter((line): line is string => Boolean(line))
    .join("\n");
}

export function createPromptInjectionLibrarySeedAttempts(
  library: PromptInjectionLibrary,
  options: PromptInjectionLibrarySeedOptions = {},
): AgentRedTeamSeedAttemptInput[] {
  const selectedCategories = options.categories
    ? new Set(options.categories)
    : undefined;
  const selectedTags = options.tags ? new Set(options.tags) : undefined;
  const maxSeeds = options.maxSeeds ?? 24;

  return library
    .listCatalog()
    .filter(
      (entry) => !selectedCategories || selectedCategories.has(entry.category),
    )
    .filter(
      (entry) =>
        !selectedTags || entry.tags.some((tag) => selectedTags.has(tag)),
    )
    .slice(0, maxSeeds)
    .map((entry) => {
      const classification = classifyEntry(entry);
      const seed: AgentRedTeamSeed = {
        source: "prompt-injection-library",
        id: entry.id,
        label: entry.name,
        category: entry.category,
        tags: entry.tags,
        deliveryHints: entry.deliveryHints,
        expectedObservation: entry.expectedObservation,
        payloadHash: entry.payloadHash,
      };

      return {
        ...classification,
        mutationChain: ["identity"],
        carrierLabel: "prompt-injection-library-ref",
        renderedPrompt: renderSeedReference(entry),
        goal: seedGoal(entry),
        seed,
      };
    });
}
