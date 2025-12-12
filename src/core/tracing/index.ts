/**
 * Weave Tracing for Tool Usage Training Data
 *
 * This module logs tool calls with full context to W&B Weave for human curation.
 * The traces can be reviewed in the Weave app and curated into datasets for
 * TRL/RL fine-tuning with tools like Tinker.
 *
 * Each trace captures:
 * - System prompt
 * - Conversation context (messages leading to the tool call)
 * - Model reasoning (if available, e.g., from thinking models)
 * - Tool call (name + arguments)
 * - Tool result (output + success/error status)
 * - Metadata (model, session, target)
 */

import type { ModelMessage } from 'ai';
import type { AIModel } from '../ai';

// ============================================================================
// Types
// ============================================================================

/**
 * Simplified message format for training context.
 * Stored as part of each tool usage trace.
 */
export interface TrainingMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  /** For assistant messages that include tool calls */
  toolCall?: {
    name: string;
    arguments: Record<string, unknown>;
  };
}

/**
 * Complete context for a tool usage training example.
 * This is what gets logged to Weave for human curation.
 */
export interface ToolUsageTrace {
  /** System prompt that was active */
  systemPrompt: string;

  /** Conversation history leading to this tool call */
  conversationContext: TrainingMessage[];

  /** Model's reasoning/thinking before the tool call (if available) */
  reasoning?: string;

  /** The tool that was called */
  toolName: string;

  /** Arguments passed to the tool */
  toolArguments: Record<string, unknown>;

  /** Whether the tool execution succeeded */
  toolSuccess: boolean;

  /** Tool output (result or error) */
  toolOutput: unknown;

  /** Error message if tool failed */
  toolError?: string;

  /** Model used for this call */
  model: string;

  /** Session identifier for grouping related traces */
  sessionId: string;

  /** Target being tested (for pentest context) */
  target?: string;

  /** Timestamp of the tool call */
  timestamp: string;
}

// ============================================================================
// Weave Module State
// ============================================================================

let weaveModule: typeof import('weave') | null = null;
let initialized = false;
let initializationFailed = false;

/**
 * Initialize Weave tracing if WANDB_API_KEY is set.
 * Returns true if Weave was successfully initialized.
 */
export async function initWeave(): Promise<boolean> {
  if (!process.env.WANDB_API_KEY) {
    return false;
  }

  if (initialized) {
    return true;
  }

  if (initializationFailed) {
    return false;
  }

  try {
    weaveModule = await import('weave');
    await weaveModule.init(process.env.WANDB_PROJECT || 'apex-tool-training-data');
    initialized = true;
    console.log('[Weave] Training data collection initialized');
    return true;
  } catch (error: any) {
    initializationFailed = true;
    weaveModule = null;
    console.warn('[Weave] Failed to initialize:', error?.message || error);
    return false;
  }
}

/**
 * Check if Weave tracing is enabled and initialized.
 */
export function isWeaveEnabled(): boolean {
  return initialized;
}

/**
 * Get the weave module (only available after initWeave succeeds).
 */
export function getWeave(): typeof import('weave') | null {
  return weaveModule;
}

// ============================================================================
// Tool Usage Trace Logging
// ============================================================================

// Cached traced function for tool usage examples
let tracedToolUsage: ((trace: ToolUsageTrace) => Promise<ToolUsageTrace>) | null = null;

function getTracedToolUsage() {
  if (tracedToolUsage) return tracedToolUsage;
  if (!weaveModule) return null;

  // This creates a Weave op that logs the full tool usage context
  // Each call appears as a trace in the Weave UI for human curation
  tracedToolUsage = weaveModule.op(
    async function toolUsageExample(trace: ToolUsageTrace): Promise<ToolUsageTrace> {
      // The function returns the trace - Weave captures input/output automatically
      return trace;
    },
    { name: 'tool_usage_example' }
  );

  return tracedToolUsage;
}

/**
 * Log a tool usage example to Weave for training data curation.
 *
 * Call this after each tool execution to capture the full context
 * needed for TRL/RL fine-tuning.
 *
 * @param params - All context needed for the training example
 */
export async function logToolUsage(params: {
  systemPrompt: string;
  messages: ModelMessage[];
  toolName: string;
  toolArguments: Record<string, unknown>;
  toolOutput: unknown;
  toolSuccess: boolean;
  toolError?: string;
  model: AIModel;
  sessionId: string;
  target?: string;
}): Promise<void> {
  if (!isWeaveEnabled()) {
    return;
  }

  const tracedFn = getTracedToolUsage();
  if (!tracedFn) return;

  try {
    // Extract reasoning from the last assistant message if present
    const reasoning = extractReasoning(params.messages);

    // Convert messages to simplified training format
    const conversationContext = convertToTrainingMessages(params.messages);

    const trace: ToolUsageTrace = {
      systemPrompt: params.systemPrompt,
      conversationContext,
      reasoning,
      toolName: params.toolName,
      toolArguments: params.toolArguments,
      toolSuccess: params.toolSuccess,
      toolOutput: params.toolOutput,
      toolError: params.toolError,
      model: params.model,
      sessionId: params.sessionId,
      target: params.target,
      timestamp: new Date().toISOString(),
    };

    await tracedFn(trace);
  } catch (error) {
    // Silently fail - don't crash the app if logging fails
    console.warn('[Weave] Failed to log tool usage:', error);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Extract reasoning/thinking from the most recent assistant message.
 * This captures chain-of-thought from thinking models.
 */
function extractReasoning(messages: ModelMessage[]): string | undefined {
  // Look backwards for the most recent assistant message with reasoning
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (!msg) continue;
    if (msg.role === 'assistant' && typeof msg.content !== 'string') {
      for (const part of msg.content) {
        if (part.type === 'reasoning') {
          return part.text;
        }
      }
    }
  }
  return undefined;
}

/**
 * Convert AI SDK ModelMessage[] to simplified TrainingMessage[] format.
 * This creates a clean representation for training data.
 */
function convertToTrainingMessages(messages: ModelMessage[]): TrainingMessage[] {
  const result: TrainingMessage[] = [];

  for (const msg of messages) {
    switch (msg.role) {
      case 'system':
        result.push({
          role: 'system',
          content: typeof msg.content === 'string' ? msg.content : '',
        });
        break;

      case 'user':
        const userContent = typeof msg.content === 'string'
          ? msg.content
          : msg.content
              .filter(part => part.type === 'text')
              .map(part => (part as { type: 'text'; text: string }).text)
              .join('\n');
        result.push({ role: 'user', content: userContent });
        break;

      case 'assistant':
        if (typeof msg.content === 'string') {
          result.push({ role: 'assistant', content: msg.content });
        } else {
          // Extract text content and tool calls
          let textContent = '';
          let toolCall: TrainingMessage['toolCall'] = undefined;

          for (const part of msg.content) {
            if (part.type === 'text') {
              textContent += part.text;
            } else if (part.type === 'reasoning') {
              // Include reasoning in a marked format
              textContent += `<reasoning>${part.text}</reasoning>`;
            } else if (part.type === 'tool-call') {
              // Capture the last tool call (there's usually just one per message)
              toolCall = {
                name: part.toolName,
                arguments: part.input as Record<string, unknown>,
              };
            }
          }

          result.push({
            role: 'assistant',
            content: textContent,
            toolCall,
          });
        }
        break;

      case 'tool':
        // Tool results
        if (Array.isArray(msg.content)) {
          for (const part of msg.content) {
            if (part.type === 'tool-result') {
              result.push({
                role: 'tool',
                content: typeof part.output === 'string'
                  ? part.output
                  : JSON.stringify(part.output),
              });
            }
          }
        }
        break;
    }
  }

  return result;
}

// ============================================================================
// Legacy Exports (for backwards compatibility during migration)
// ============================================================================

/**
 * @deprecated Use logToolUsage instead. This is a no-op wrapper for migration.
 */
export async function withTracedTool<T>(
  _toolName: string,
  _input: any,
  executeFn: () => Promise<T>
): Promise<T> {
  // Just execute the function - actual logging happens via logToolUsage
  return executeFn();
}

/**
 * @deprecated Use logToolUsage instead. This is a no-op wrapper for migration.
 */
export async function withTracedOrchestrator<T>(
  _params: { target: string; sessionId: string; model: string },
  executeFn: () => Promise<T>
): Promise<T> {
  return executeFn();
}

/**
 * @deprecated Use logToolUsage instead. This is a no-op wrapper for migration.
 */
export async function withTracedSubagent<T>(
  _agentType: string,
  _target: string,
  _subagentId: string,
  executeFn: () => Promise<T>
): Promise<T> {
  return executeFn();
}
