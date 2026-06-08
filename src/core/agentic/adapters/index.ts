import type { AgenticAdapterConfig } from "../config";
import { HttpJsonAdapter } from "./httpJson";
import { MockAdapter } from "./mock";
import { OpenAICompatibleAdapter } from "./openaiCompatible";
import type { TargetAdapter } from "./types";

export type { CreateSessionInput, TargetAdapter } from "./types";

export interface CreateAdapterOptions {
  /** Force the mock adapter regardless of config (dry-run / tests). */
  dryRun?: boolean;
  /** Per-request timeout in ms. */
  timeoutMs?: number;
}

/** Build a TargetAdapter from config. */
export function createTargetAdapter(
  cfg: AgenticAdapterConfig,
  opts: CreateAdapterOptions = {},
): TargetAdapter {
  if (opts.dryRun || cfg.kind === "mock") return new MockAdapter();
  switch (cfg.kind) {
    case "openai-compatible":
      return new OpenAICompatibleAdapter(cfg, opts.timeoutMs);
    case "http-json":
      return new HttpJsonAdapter(cfg, opts.timeoutMs);
    default:
      throw new Error(`Unknown agentic adapter kind: ${cfg.kind}`);
  }
}
