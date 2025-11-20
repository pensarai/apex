// Braintrust Tracing Utilities
//
// Provides safe wrappers for tracing agent operations, tool calls, and AI interactions.
// Each trace function wraps execution in a Braintrust span for observability.
//
// The tracing functions follow a consistent pattern:
// 1. Check if Braintrust is enabled (early return if disabled)
// 2. Wrap execution in logger.traced() with span name and metadata
// 3. logger.traced() handles timing, error capture, and span lifecycle automatically
// 4. Return result or re-throw errors transparently
//
// If Braintrust is disabled, operations execute normally without tracing overhead.

import { getBraintrustLogger } from './client';
import { isBraintrustEnabled } from './config';
import type { AgentSpanMetadata, ToolSpanMetadata, AISpanMetadata } from './types';
import type { Config } from '../config/config';

// Type for metadata updater callback provided to trace functions.
// Allows updating span metadata mid-execution (e.g., adding final metrics).
type MetadataUpdater<T> = (updates: Partial<T>) => void;

// Traces an agent execution with automatic timing and metadata capture.
// Wraps an async function with Braintrust span tracking. If Braintrust is disabled,
// executes the function normally without tracing overhead.
//
// The function receives a metadata updater callback to log additional metrics during execution.
//
// Example:
//   const config = await getConfig();
//   await traceAgent(config, 'pentest-agent', { agent_type: 'pentest', model: 'gpt-4', ... }, async (updateMetadata) => {
//     const results = await runPentest();
//     updateMetadata({ findings_count: results.length });
//     return results;
//   });
export async function traceAgent<T>(
  config: Config,
  name: string,
  meta: AgentSpanMetadata,
  fn: (updateMetadata: MetadataUpdater<AgentSpanMetadata>) => Promise<T>,
): Promise<T> {
  // Early return if disabled to avoid overhead
  if (!isBraintrustEnabled(config)) {
    return await fn(() => {}); // Provide no-op updater
  }

  const logger = getBraintrustLogger(config);
  if (!logger) {
    return await fn(() => {}); // Provide no-op updater
  }

  try {
    return await logger.traced(
      async (span) => {
        // Log initial metadata immediately
        if (span) {
          span.log({
            input: meta,
            metadata: meta,
          } as any);
        }

        // Provide metadata updater that logs directly to span
        const updateMetadata = (updates: Partial<AgentSpanMetadata>) => {
          if (span) {
            // Log updates as metadata
            span.log({
              metadata: { ...meta, ...updates },
            } as any);
          }
        };

        return await fn(updateMetadata);
      },
      {
        name: `agent:${name}`,
      }
    );
  } catch (err) {
    // If span creation fails, fall back to executing without tracing
    console.warn('[Braintrust] Failed to create agent span, executing without tracing:', (err as Error).message);
    return await fn(() => {}); // Provide no-op updater
  }
}

// Traces a tool call execution with automatic timing and metadata capture.
// Wraps an async function with Braintrust span tracking. If Braintrust is disabled,
// executes the function normally without tracing overhead.
//
// The function receives a metadata updater callback to log additional metrics during execution.
//
// Example:
//   const config = await getConfig();
//   await traceToolCall(config, 'nmap-scan', { tool_name: 'nmap', endpoint: '192.168.1.1', ... }, async (updateMetadata) => {
//     const result = await runNmapScan();
//     updateMetadata({ success: true, duration_ms: 1500 });
//     return result;
//   });
export async function traceToolCall<T>(
  config: Config,
  name: string,
  meta: ToolSpanMetadata,
  fn: (updateMetadata: MetadataUpdater<ToolSpanMetadata>) => Promise<T>,
): Promise<T> {
  // Early return if disabled to avoid overhead
  if (!isBraintrustEnabled(config)) {
    return await fn(() => {}); // Provide no-op updater
  }

  const logger = getBraintrustLogger(config);
  if (!logger) {
    return await fn(() => {}); // Provide no-op updater
  }

  try {
    return await logger.traced(
      async (span) => {
        // Provide metadata updater that logs to the span as metadata
        // Note: Braintrust's log() expects ExperimentLogPartialArgs, so we pass as metadata field
        const updateMetadata = (updates: Partial<ToolSpanMetadata>) => {
          if (span) {
            span.log({ metadata: updates } as any);
          }
        };
        return await fn(updateMetadata);
      },
      {
        name: `tool:${name}`,
        ...meta,
      }
    );
  } catch (err) {
    // If span creation fails, fall back to executing without tracing
    console.warn('[Braintrust] Failed to create tool span, executing without tracing:', (err as Error).message);
    return await fn(() => {}); // Provide no-op updater
  }
}

// Traces an AI model call with automatic timing and token usage tracking.
// Wraps an async function with Braintrust span tracking. If Braintrust is disabled,
// executes the function normally without tracing overhead.
//
// The function receives a metadata updater callback to log token usage and other metrics.
//
// Example:
//   const config = await getConfig();
//   await traceAICall(config, 'openai-completion', { model: 'gpt-4', provider: 'openai', ... }, async (updateMetadata) => {
//     const result = await callOpenAI();
//     updateMetadata({ prompt_tokens: 100, completion_tokens: 50 });
//     return result;
//   });
export async function traceAICall<T>(
  config: Config,
  name: string,
  meta: AISpanMetadata,
  fn: (updateMetadata: MetadataUpdater<AISpanMetadata>) => Promise<T>,
): Promise<T> {
  // Early return if disabled to avoid overhead
  if (!isBraintrustEnabled(config)) {
    return await fn(() => {}); // Provide no-op updater
  }

  const logger = getBraintrustLogger(config);
  if (!logger) {
    return await fn(() => {}); // Provide no-op updater
  }

  try {
    return await logger.traced(
      async (span) => {
        // Provide metadata updater that logs to the span as metadata
        // Note: Braintrust's log() expects ExperimentLogPartialArgs, so we pass as metadata field
        const updateMetadata = (updates: Partial<AISpanMetadata>) => {
          if (span) {
            span.log({ metadata: updates } as any);
          }
        };
        return await fn(updateMetadata);
      },
      {
        name: `ai:${name}`,
        ...meta,
      }
    );
  } catch (err) {
    // If span creation fails, fall back to executing without tracing
    console.warn('[Braintrust] Failed to create AI span, executing without tracing:', (err as Error).message);
    return await fn(() => {}); // Provide no-op updater
  }
}

