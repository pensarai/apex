// Braintrust Integration Module
//
// Main entry point for the Braintrust observability integration.
// Exports all public APIs for configuration, tracing, and data sanitization.
//
// Usage:
//   import { traceAgent, sanitizeToolInput, isBraintrustEnabled } from '@/core/braintrust';
//
//   if (isBraintrustEnabled()) {
//     await traceAgent('my-agent', metadata, async () => {
//       // agent logic
//     });
//   }

// Configuration
export { getBraintrustConfig, isBraintrustEnabled } from './config';

// Client management
export { getBraintrustLogger, safeFlush } from './client';

// Tracing utilities
export { traceAgent, traceToolCall, traceAICall } from './tracer';

// Data sanitization
export {
  sanitizeHeaders,
  sanitizeQueryParams,
  sanitizeBody,
  sanitizeToolInput,
  sanitizeToolOutput,
} from './sanitizer';

// Type exports
export type {
  BraintrustConfig,
  AgentSpanMetadata,
  ToolSpanMetadata,
  AISpanMetadata,
} from './types';

export { SENSITIVE_PATTERNS } from './types';
