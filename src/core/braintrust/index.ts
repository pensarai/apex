// Braintrust Integration Module
//
// Main entry point for the Braintrust observability integration.
// Provides a minimal, clean API for tracing agents, tools, and AI calls.
//
// Configuration can be set via environment variables (recommended) or ~/.pensar/config.json:
//   export BRAINTRUST_API_KEY="your-api-key"
//   export BRAINTRUST_PROJECT_NAME="apex-pentest"  # optional
//   export BRAINTRUST_ENVIRONMENT="dev"            # optional: dev|staging|prod
//
// Usage:
//   import { traceAgent, isBraintrustEnabled } from '@/core/braintrust';
//   import { config } from '@/core/config';
//
//   const appConfig = await config.get();
//   if (isBraintrustEnabled(appConfig)) {
//     await traceAgent(appConfig, 'my-agent', metadata, async (updateMetadata) => {
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
