// Braintrust Tracing Utilities
//
// Provides safe wrappers for tracing agent operations, tool calls, and AI interactions.
// Each trace function measures execution time, captures metadata, and handles errors gracefully.
//
// The tracing functions follow a consistent pattern:
// 1. Start a span with prefixed name (agent:/tool:/ai:)
// 2. Execute the provided async function
// 3. Measure duration and update metadata
// 4. End span with error if thrown
// 5. Re-throw errors to preserve normal error handling
//
// If Braintrust is disabled or spans fail to create, operations continue without tracing.

import { getBraintrustClient } from './client';
import type { AgentSpanMetadata, ToolSpanMetadata, AISpanMetadata } from './types';

type Span = any; // tighten with real Braintrust type

// Safely starts a Braintrust span with the given name and metadata.
// Returns null if client is unavailable or span creation fails.
// Errors are logged but don't interrupt execution.
function startSpanSafe(name: string, metadata: AgentSpanMetadata | ToolSpanMetadata | AISpanMetadata): Span | null {
  const client = getBraintrustClient();
  if (!client) return null;

  try {
    // TODO: Implement real span creation once SDK is integrated
    // return client.startSpan({ name, metadata });
    return {}; // placeholder span
  } catch (err) {
    console.warn('[Braintrust] Failed to start span, continuing without tracing:', (err as Error).message);
    return null;
  }
}

// Safely ends a Braintrust span, optionally recording an error.
// Failures during span ending are logged but don't interrupt execution.
function endSpanSafe(span: Span | null, error?: unknown) {
  if (!span) return;
  try {
    // TODO: Implement real span ending once SDK is integrated
    // span.end({ error });
  } catch (err) {
    console.warn('[Braintrust] Failed to end span, ignoring:', (err as Error).message);
  }
}

// Traces an agent execution with timing and metadata capture.
// Wraps an async function with Braintrust span tracking, measuring duration
// and recording success/failure. Metadata is enriched with duration_ms after execution.
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
  const span = startSpanSafe(`agent:${name}`, meta);
  const start = Date.now();

  try {
    const result = await fn();
    meta.duration_ms = Date.now() - start;
    endSpanSafe(span, undefined);
    return result;
  } catch (err) {
    meta.duration_ms = Date.now() - start;
    endSpanSafe(span, err);
    throw err;
  }
}

// Traces a tool call execution with timing and metadata capture.
// Wraps an async function with Braintrust span tracking, measuring duration
// and recording success/failure. Metadata is enriched with duration_ms after execution.
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
  const span = startSpanSafe(`tool:${name}`, meta);
  const start = Date.now();

  try {
    const result = await fn();
    meta.duration_ms = Date.now() - start;
    endSpanSafe(span, undefined);
    return result;
  } catch (err) {
    meta.duration_ms = Date.now() - start;
    endSpanSafe(span, err);
    throw err;
  }
}

// Traces an AI model call with timing and token usage tracking.
// Wraps an async function with Braintrust span tracking, measuring latency
// and recording model usage metrics. Metadata is enriched with latency_ms after execution.
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
  const span = startSpanSafe(`ai:${name}`, meta);
  const start = Date.now();

  try {
    const result = await fn();
    meta.latency_ms = Date.now() - start;
    endSpanSafe(span, undefined);
    return result;
  } catch (err) {
    meta.latency_ms = Date.now() - start;
    endSpanSafe(span, err);
    throw err;
  }
}
