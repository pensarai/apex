/**
 * Threat Model Benchmark — Match Classifier
 *
 * Binary yes/no LLM classifier for fuzzy ground truth matching.
 * Batches up to 10 items per API call to minimize cost.
 */

import { z } from "zod";
import { generateObjectResponse } from "../../../../src/core/ai/ai";
import type { AIModel } from "../../../../src/core/ai/ai";
import type { AIAuthConfig } from "../../../../src/core/ai/utils";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const MatchResultSchema = z.object({
  matches: z.array(
    z.object({
      itemId: z.string(),
      matched: z.boolean(),
      evidence: z.string().optional(),
    }),
  ),
});

export interface MatchItem {
  id: string;
  description: string;
}

export interface MatchResult {
  itemId: string;
  matched: boolean;
  evidence?: string;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are a precise classifier. You determine whether items from a ground truth list are covered by a threat model output section.

Rules:
- An item is "matched" if the threat model output describes, references, or covers the same concept, even in different words.
- Be generous with synonyms and paraphrasing, but strict about substance — the core concept must be present.
- For vulnerability matching: the threat model must describe an attack that exploits the same root cause and entry point, not just mention the same category.
- Return a JSON object with a "matches" array. Each entry has "itemId", "matched" (boolean), and optional "evidence" (a brief quote from the output that covers it).`;

async function classifyBatch(
  items: MatchItem[],
  outputSection: string,
  model: AIModel,
  authConfig?: AIAuthConfig,
): Promise<MatchResult[]> {
  const itemList = items
    .map((item) => `- [${item.id}] ${item.description}`)
    .join("\n");

  const prompt = `## Ground Truth Items

${itemList}

## Threat Model Output Section

${outputSection.slice(0, 12000)}

For each ground truth item, determine if it is covered by the threat model output.`;

  const result = await generateObjectResponse({
    model,
    schema: MatchResultSchema,
    prompt,
    system: SYSTEM_PROMPT,
    temperature: 0,
    authConfig,
  });

  return result?.matches ?? [];
}

/**
 * Classify a list of ground truth items against a threat model output section.
 * Batches items in groups of 10 to minimize API calls.
 */
export async function classifyMatches(
  items: MatchItem[],
  outputSection: string,
  model: AIModel,
  authConfig?: AIAuthConfig,
): Promise<Map<string, MatchResult>> {
  const results = new Map<string, MatchResult>();

  // Batch in groups of 10
  for (let i = 0; i < items.length; i += 10) {
    const batch = items.slice(i, i + 10);
    const batchResults = await classifyBatch(
      batch,
      outputSection,
      model,
      authConfig,
    );

    for (const r of batchResults) {
      results.set(r.itemId, r);
    }

    // Fill in any items the LLM missed in its response
    for (const item of batch) {
      if (!results.has(item.id)) {
        results.set(item.id, { itemId: item.id, matched: false });
      }
    }
  }

  return results;
}
