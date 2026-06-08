import { z } from "zod";

/**
 * Config schema for an agentic (AI agent / LLM app) scan target. Persisted on
 * `SessionConfig.agentic` and consumed by the agentic workflow + adapters.
 *
 * Generic-first: two built-in adapter kinds cover most targets without
 * vendor-specific code — `openai-compatible` (chat-completions shape) and
 * `http-json` (configurable request/response field mapping). `mock` is for
 * dry-run / tests.
 */

export const AgenticAuthSchema = z.object({
  /** Header name carrying the credential (default "Authorization"). */
  header: z.string().optional(),
  /** Env var the secret is read from at runtime — never persisted to disk. */
  valueEnv: z.string().optional(),
  /** "bearer" prefixes the value with "Bearer "; "raw" sends it verbatim. */
  scheme: z.enum(["bearer", "raw"]).optional(),
});

export const AgenticAdapterSchema = z.object({
  kind: z.enum(["openai-compatible", "http-json", "mock"]),
  /** HTTP endpoint the adapter posts to. */
  endpoint: z.string(),
  /** Model id for openai-compatible endpoints (optional). */
  model: z.string().optional(),
  auth: AgenticAuthSchema.optional(),
  /** Request shaping for the http-json adapter. */
  request: z
    .object({
      /** Dot-path where the user message string is injected into the body. */
      messagePath: z.string().optional(),
      /** Static body template the message is merged into. */
      template: z.record(z.string(), z.unknown()).optional(),
    })
    .optional(),
  /** Response shaping — dot-path to the assistant text in the JSON response. */
  response: z
    .object({
      textPath: z.string().optional(),
    })
    .optional(),
});

export const AgenticCapabilitiesSchema = z.object({
  /** Agent can call tools / make outbound HTTP requests. */
  tools: z.boolean().optional(),
  /** Agent retrieves from a knowledge base / connected sources. */
  knowledge: z.boolean().optional(),
  /** Agent delegates to sub-agents / other agents. */
  subagents: z.boolean().optional(),
  /** The surface renders markdown (images/links) from agent output. */
  rendersMarkdown: z.boolean().optional(),
});

export const AgenticCanarySchema = z.object({
  /** Public base URL of the canary collector (tunnel) reachable by the agent. */
  publicUrl: z.string().optional(),
  /** Local collector port (default 8731). */
  port: z.number().optional(),
});

export const AgenticConfigObject = z.object({
  /** Endpoint URL (mirrors session.targets[0]; kept for convenience). */
  endpoint: z.string(),
  adapter: AgenticAdapterSchema,
  capabilities: AgenticCapabilitiesSchema.optional(),
  canary: AgenticCanarySchema.optional(),
  /** Restrict the run to these case categories (default: all applicable). */
  categories: z.array(z.string()).optional(),
});

export type AgenticAuth = z.infer<typeof AgenticAuthSchema>;
export type AgenticAdapterConfig = z.infer<typeof AgenticAdapterSchema>;
export type AgenticCapabilities = z.infer<typeof AgenticCapabilitiesSchema>;
export type AgenticConfig = z.infer<typeof AgenticConfigObject>;
