// Braintrust Integration Module
//
// Main entry point for the Braintrust observability integration.
// Provides a minimal, clean API for tracing agents, tools, and AI calls.
//
// Configuration is stored in ~/.pensar/config.json via the centralized config system.
// To enable Braintrust, add your API key to the config file.
//
// Usage:
//   import { traceAgent, isBraintrustEnabled } from '@/core/braintrust';
//   import { get as getConfig } from '@/core/config';
//
//   const config = await getConfig();
//   if (isBraintrustEnabled(config)) {
//     await traceAgent(config, 'my-agent', metadata, async (updateMetadata) => {
//       // agent logic
//       updateMetadata({ findings_count: 5 });
//     });
//   }

// Configuration
export { isBraintrustEnabled } from './config';

// Client management
export { flushBraintrust } from './client';

// Tracing utilities
export { traceAgent, traceToolCall, traceAICall } from './tracer';

// Data sanitization (main entry points only)
export { sanitizeToolInput, sanitizeToolOutput } from './sanitizer';

// Type exports
export type {
  AgentSpanMetadata,
  ToolSpanMetadata,
  AISpanMetadata,
} from './types';
