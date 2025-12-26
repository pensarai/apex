/**
 * Static Analysis Module
 *
 * LLM-augmented Static Application Security Testing (SAST)
 * Analyzes git repositories using an 8-agent pipeline.
 */

// Types
export * from './types';

// Workspace management
export * from './workspace';

// Cache management
export * from './cache';

// Orchestrator
export { runStaticOrchestrator } from './orchestrator';

// External tool detection
export { detectAvailableTools, hasMinimumTools, getInstallInstructions } from './external/detector';

// Re-export commonly used types for convenience
export type {
  StaticAnalysisState,
  StaticFinding,
  StaticOrchestratorInput,
  StaticOrchestratorResult,
  StaticAnalysisProgress,
  StaticSubagent,
  RepoInventory,
  CodeIndex,
  ToolAvailability,
} from './types';
