import { writeFile } from "node:fs/promises";
import { z } from "zod";
import { OPENROUTER_MODELS } from "../src/core/ai/models/openrouter";

const source = "https://openrouter.ai/api/v1/models";
const effort = z.enum([
  "none",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
]);
const reasoning = z.object({
  mandatory: z.boolean().optional(),
  default_enabled: z.boolean().optional(),
  supported_efforts: z.array(effort).nullable().optional(),
  default_effort: effort.optional(),
  supports_max_tokens: z.boolean().optional(),
});
const response = await fetch(source, { signal: AbortSignal.timeout(30_000) });
if (!response.ok)
  throw new Error(`Model catalog returned HTTP ${response.status}`);
const payload = z
  .object({
    data: z.array(
      z.object({ id: z.string(), reasoning: z.unknown().optional() }),
    ),
  })
  .parse(await response.json());
const catalog = new Map(payload.data.map((model) => [model.id, model]));
const models = Object.fromEntries(
  OPENROUTER_MODELS.map(({ id }) => {
    const entry = catalog.get(id);
    return [
      id,
      entry?.reasoning == null ? null : reasoning.parse(entry.reasoning),
    ];
  }),
);
await writeFile(
  new URL("../src/core/ai/models/openrouter-reasoning.json", import.meta.url),
  `${JSON.stringify({ source, reviewedAt: new Date().toISOString().slice(0, 10), models }, null, 2)}\n`,
);
console.log(
  `Updated reasoning capabilities for ${Object.keys(models).length} OpenRouter routes. Review the diff and run the reasoning tests.`,
);
