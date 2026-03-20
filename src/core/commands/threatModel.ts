import { join } from "path";
import { mkdirSync, writeFileSync } from "fs";
import type {
  SchemaBackedCommand,
  CommandContext,
  CommandOutput,
} from "./types";
import {
  ThreatModelResultSchema,
  type ThreatModelAgentResult,
  type ThreatModelResult,
} from "../agents/specialized/threatModel/types";
import {
  THREAT_MODEL_SYSTEM_PROMPT,
  buildThreatModelObjective,
} from "../agents/specialized/threatModel/prompts";
import { serializeThreatModelToMarkdown } from "../agents/specialized/threatModel/serialize";

// ---------------------------------------------------------------------------
// Tool allowlist
// ---------------------------------------------------------------------------

const THREAT_MODEL_TOOLS = [
  "read_file",
  "list_files",
  "grep",
  "execute_command",
  "document_asset",
] as const;

// ---------------------------------------------------------------------------
// Command definition
// ---------------------------------------------------------------------------

export const threatModelCommand: SchemaBackedCommand<ThreatModelAgentResult> = {
  name: "threat-model",
  description:
    "Generate an application-centric threat model from source code analysis",
  aliases: ["tm"],

  system: THREAT_MODEL_SYSTEM_PROMPT,

  buildPrompt: (input) =>
    buildThreatModelObjective(input.cwd, input.applicationIdentity),

  activeTools: [...THREAT_MODEL_TOOLS],

  responseSchema: ThreatModelResultSchema,

  onResult: async (
    agentResult: ThreatModelAgentResult,
    ctx: CommandContext,
  ): Promise<CommandOutput> => {
    const threatModelDir = join(ctx.session.rootPath, "threat-model");
    mkdirSync(threatModelDir, { recursive: true });

    const result = assembleResult(agentResult, ctx);

    const jsonPath = join(threatModelDir, "threat-model.json");
    const mdPath = join(threatModelDir, "threat-model.md");
    writeFileSync(jsonPath, JSON.stringify(result, null, 2));
    writeFileSync(mdPath, serializeThreatModelToMarkdown(result));

    const { bySeverity, totalAttackPaths } = result.summary;
    return {
      files: { json: jsonPath, markdown: mdPath },
      summary: `Threat model complete — ${totalAttackPaths} attack paths: ${bySeverity.critical} critical, ${bySeverity.high} high, ${bySeverity.medium} medium, ${bySeverity.low} low`,
    };
  },
};

// ---------------------------------------------------------------------------
// Result assembly
// ---------------------------------------------------------------------------

/**
 * Merge the agent's raw structured output with computed metadata and summary
 * fields to produce the final {@link ThreatModelResult}.
 */
export function assembleResult(
  agentResult: ThreatModelAgentResult,
  ctx: CommandContext,
): ThreatModelResult {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const ap of agentResult.attackPaths) {
    bySeverity[ap.severity]++;
  }

  const severityOrder = ["critical", "high", "medium", "low"] as const;
  const sorted = [...agentResult.attackPaths].sort(
    (a, b) =>
      severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity),
  );

  const threatModelDir = join(ctx.session.rootPath, "threat-model");

  return {
    metadata: {
      mode: "whitebox",
      target: ctx.cwd,
      generatedAt: new Date().toISOString(),
      modelUsed: ctx.model ?? "unknown",
      schemaVersion: "2.0.0",
    },
    ...agentResult,
    summary: {
      totalComponents: agentResult.architecture.components.length,
      totalDataFlows: agentResult.architecture.dataFlows.length,
      totalAttackPaths: agentResult.attackPaths.length,
      bySeverity,
      topRisks: sorted.slice(0, 10).map((ap) => ap.id),
    },
    files: {
      markdownPath: join(threatModelDir, "threat-model.md"),
      jsonPath: join(threatModelDir, "threat-model.json"),
    },
  };
}
