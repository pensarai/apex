import { isWeaveEnabled, getWeave } from './index';
import type { AIModel } from '../ai';

export interface LLMCallData {
  model: AIModel;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  finishReason?: string;
  toolCallCount?: number;
}

// Cached traced function - created lazily after Weave is initialized
let tracedLogLLMCall: ((data: LLMCallData) => Promise<LLMCallData>) | null = null;

/**
 * Get or create the traced LLM call logger.
 */
function getTracedLogLLMCall() {
  if (tracedLogLLMCall) {
    return tracedLogLLMCall;
  }

  const weave = getWeave();
  if (!weave) {
    return null;
  }

  tracedLogLLMCall = weave.op(async function llmCall(
    data: LLMCallData
  ): Promise<LLMCallData> {
    return data;
  });

  return tracedLogLLMCall;
}

/**
 * Conditionally log an LLM call only if Weave is enabled.
 * Creates a child span in the current Weave trace context.
 */
export async function maybeLogLLMCall(data: LLMCallData): Promise<void> {
  if (!isWeaveEnabled()) {
    return;
  }

  const tracedFn = getTracedLogLLMCall();
  if (tracedFn) {
    try {
      await tracedFn(data);
    } catch (error) {
      // Silently fail - don't crash the app if Weave logging fails
    }
  }
}
