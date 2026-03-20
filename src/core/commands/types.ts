import type { z } from "zod";
import type { SessionInfo } from "../session";

// ---------------------------------------------------------------------------
// Schema-Backed Command
// ---------------------------------------------------------------------------

/**
 * A general pattern for prompted agents with structured (Zod-validated) output.
 *
 * Each command bundles everything needed to run an agent end-to-end:
 * the prompts, the tools it may use, the output schema, and a handler
 * that persists / transforms the result.
 *
 * @typeParam TResult - The Zod-inferred type the agent must produce.
 */
export interface SchemaBackedCommand<TResult> {
  /** Command name (used as slash command, e.g. "threat-model") */
  name: string;

  /** Short description for help text */
  description: string;

  /** Aliases (e.g. ["tm"]) */
  aliases?: string[];

  /** System prompt for the agent */
  system: string;

  /** Build the user prompt from the command's input */
  buildPrompt: (input: CommandInput) => string;

  /** Tools the agent can use */
  activeTools: string[];

  /** Zod schema for structured output */
  responseSchema: z.ZodSchema<TResult>;

  /** Handle the structured result (persist, transform, etc.) */
  onResult: (result: TResult, ctx: CommandContext) => Promise<CommandOutput>;
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

export interface CommandInput {
  cwd: string;
  session: SessionInfo;
  applicationIdentity?: string;
}

export interface CommandContext {
  session: SessionInfo;
  cwd: string;
  model?: string;
}

export interface CommandOutput {
  /** Paths to generated files */
  files: Record<string, string>;
  /** Summary message shown to user */
  summary: string;
}
