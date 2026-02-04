/**
 * MetaTestingAgent Module
 *
 * A cognitive security testing agent inspired by CyberAutoAgent architecture.
 *
 * Key patterns implemented:
 * - Single agent with meta capabilities (vs multi-agent pipeline)
 * - Confidence-driven reasoning (KNOW → THINK → TEST → VALIDATE)
 * - Plans as external working memory with checkpoint protocol
 * - Meta-prompting for runtime optimization
 * - POC-driven vulnerability validation (bash/python)
 */

// Main agents
export {
  runMetaVulnerabilityTestAgent,
  type MetaVulnerabilityTestInput,
  type MetaVulnerabilityTestResult,
  type SpawnVulnerabilityTestRequest,
} from './metaVulnerabilityTestAgent';

// Types
export type {
  // Core types
  VulnerabilityClass,
  PhaseStatus,
  Phase,
  PentestPlan,
  Adaptation,
  CognitiveState,
  PromptOptimization,
  PocType,

  // Input/Output types
  CreatePocInput,
  CreatePocResult,
  DocumentFindingInput,
  DocumentFindingResult,
  StorePlanInput,
  StoreAdaptationInput,

  // Agent types
  MetaTestingSessionInfo,
  AuthenticationInfo,
  MetaTestingAgentInput,
  MetaTestingProgressStatus,
  MetaTestingAgentResult,
} from './types';

// Schemas (for tool parameter validation)
export {
  CreatePocSchema,
  DocumentFindingSchema,
  StorePlanSchema,
  StoreAdaptationSchema,
} from './types';

// Tools (for custom agent construction)
export { createPocTool, createDocumentFindingTool } from './pocTools';
export { createPlanMemoryTools, loadAdaptations, loadPlan, BUDGET_CHECKPOINTS } from './planMemory';
export { createPromptOptimizerTool, loadOptimizedPrompt, loadOptimization } from './promptOptimizer';

// Prompts
export { buildMetaTestingPrompt, buildUserPrompt, META_TESTING_SYSTEM_PROMPT } from './prompts/execution';
