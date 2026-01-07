/**
 * Static Analysis Agents
 *
 * 9-agent pipeline for LLM-augmented SAST:
 * 1. RepoIntake - Analyze repository structure
 * 2. IndexGraph - Build code navigation index (symbol/import graph, security function registry)
 * 3. Analyzer - Run static analysis tools
 * 4. SpecSynth - LLM synthesizes custom Semgrep rules and Joern taint queries
 * 5. VulRAG - Enrich findings with Nuclei template vulnerability data
 * 6. Localize - Precise dataflow localization with trace narratives
 * 7. Triage - Deduplicate and rank findings
 * 8. ExploitSynth - Generate POC exploits to prove vulnerabilities
 * 9. Report - Generate final reports
 */

export { runRepoIntakeAgent } from './repo-intake';
export type { RepoIntakeInput } from './repo-intake';

export { runIndexGraphAgent } from './index-graph';
export type { IndexGraphInput } from './index-graph';

export { runAnalyzerAgent } from './analyzer';
export type { AnalyzerInput } from './analyzer';

export { runSpecSynthAgent } from './spec-synth';
export type { SpecSynthInput } from './spec-synth';

export { runTriageAgent } from './triage';
export type { TriageInput } from './triage';

export { runExploitSynthAgent } from './exploit-synth';
export type { ExploitSynthInput } from './exploit-synth';

export { runReportAgent } from './report';
export type { ReportInput } from './report';

// VulRAG agent - enriches findings with Nuclei template data
export { runVulRAGAgent, enrichFindingDirect } from './vul-rag';
export type { VulRAGInput } from './vul-rag';

// Localize agent - dataflow analysis
export { runLocalizeAgent } from './stubs';
export type { StubAgentInput } from './stubs';
