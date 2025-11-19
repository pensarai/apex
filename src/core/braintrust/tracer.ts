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

// Traces an agent execution with automatic timing and metadata capture.
// Wraps an async function with Braintrust span tracking. If Braintrust is disabled,
// executes the function normally without tracing overhead.
//
// Example:
//   await traceAgent('pentest-agent', { agent_type: 'pentest', model: 'gpt-4', ... }, async () => {
//     return await runPentest();
//   });
export async function traceAgent<T>(
  name: string,
  meta: AgentSpanMetadata,
  fn: () => Promise<T>,
): Promise<T> {
  // Early return if disabled to avoid overhead
  if (!isBraintrustEnabled()) {
    return await fn();
  }

  const logger = getBraintrustLogger();
  if (!logger) {
    return await fn();
  }

  try {
    return await logger.traced(
      async (span) => {
        // Span is available for manual logging if needed
        // span.log({ ... })
        return await fn();
      },
      {
        name: `agent:${name}`,
        ...meta,
      }
    );
  } catch (err) {
    // If span creation fails, fall back to executing without tracing
    console.warn('[Braintrust] Failed to create agent span, executing without tracing:', (err as Error).message);
    return await fn();
  }
}

// Traces a tool call execution with automatic timing and metadata capture.
// Wraps an async function with Braintrust span tracking. If Braintrust is disabled,
// executes the function normally without tracing overhead.
//
// Example:
//   await traceToolCall('nmap-scan', { tool_name: 'nmap', endpoint: '192.168.1.1', ... }, async () => {
//     return await runNmapScan();
//   });
export async function traceToolCall<T>(
  name: string,
  meta: ToolSpanMetadata,
  fn: () => Promise<T>,
): Promise<T> {
  // Early return if disabled to avoid overhead
  if (!isBraintrustEnabled()) {
    return await fn();
  }

  const logger = getBraintrustLogger();
  if (!logger) {
    return await fn();
  }

  try {
    return await logger.traced(
      async (span) => await fn(),
      {
        name: `tool:${name}`,
        ...meta,
      }
    );
  } catch (err) {
    // If span creation fails, fall back to executing without tracing
    console.warn('[Braintrust] Failed to create tool span, executing without tracing:', (err as Error).message);
    return await fn();
  }
}

// Traces an AI model call with automatic timing and token usage tracking.
// Wraps an async function with Braintrust span tracking. If Braintrust is disabled,
// executes the function normally without tracing overhead.
//
// Example:
//   await traceAICall('openai-completion', { model: 'gpt-4', provider: 'openai', ... }, async () => {
//     return await callOpenAI();
//   });
export async function traceAICall<T>(
  name: string,
  meta: AISpanMetadata,
  fn: () => Promise<T>,
): Promise<T> {
  // Early return if disabled to avoid overhead
  if (!isBraintrustEnabled()) {
    return await fn();
  }

  const logger = getBraintrustLogger();
  if (!logger) {
    return await fn();
  }

  try {
    return await logger.traced(
      async (span) => await fn(),
      {
        name: `ai:${name}`,
        ...meta,
      }
    );
  } catch (err) {
    // If span creation fails, fall back to executing without tracing
    console.warn('[Braintrust] Failed to create AI span, executing without tracing:', (err as Error).message);
    return await fn();
  }
}

