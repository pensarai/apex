/**
 * Static Analysis Agents
 *
 * 8-agent pipeline for LLM-augmented SAST:
 * 1. RepoIntake - Analyze repository structure
 * 2. IndexGraph - Build code navigation index (stub)
 * 3. Analyzer - Run static analysis tools
 * 4. SpecSynth - Synthesize custom rules (stub)
 * 5. VulRAG - Enrich with vulnerability knowledge (stub)
 * 6. Localize - Precise localization with traces
 * 7. Triage - Deduplicate and rank findings
 * 8. Report - Generate final reports
 */

export { runRepoIntakeAgent } from './repo-intake';
export type { RepoIntakeInput } from './repo-intake';

export { runAnalyzerAgent } from './analyzer';
export type { AnalyzerInput } from './analyzer';

export { runTriageAgent } from './triage';
export type { TriageInput } from './triage';

export { runReportAgent } from './report';
export type { ReportInput } from './report';

// Stub agents (passthrough or minimal implementation)
export {
  runIndexGraphAgent,
  runSpecSynthAgent,
  runVulRAGAgent,
  runLocalizeAgent,
} from './stubs';
export type { StubAgentInput } from './stubs';
