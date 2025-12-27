/**
 * Static Analysis Types
 *
 * TypeScript interfaces for the LLM-SAST static analysis system.
 * These types define the state contract between agents and the finding schema.
 */

import type { AIModel } from '../ai';
import type { Session } from '../session';

// ============================================================================
// Pipeline Stage Types
// ============================================================================

export type StaticAnalysisStage =
  | 'repo-intake'
  | 'index-graph'
  | 'analyzer'
  | 'spec-synth'
  | 'vul-rag'
  | 'localize'
  | 'triage'
  | 'exploit-synth'
  | 'report';

export const STAGE_ORDER: StaticAnalysisStage[] = [
  'repo-intake',
  'index-graph',
  'analyzer',
  'spec-synth',
  'vul-rag',
  'localize',
  'triage',
  'exploit-synth',
  'report',
];

export const STAGE_NAMES: Record<StaticAnalysisStage, string> = {
  'repo-intake': 'Repository Intake',
  'index-graph': 'Code Indexing',
  'analyzer': 'Static Analysis',
  'spec-synth': 'Spec Synthesis',
  'vul-rag': 'Knowledge Enrichment',
  'localize': 'Localization',
  'triage': 'Triage & Dedup',
  'exploit-synth': 'Exploit Synthesis',
  'report': 'Report Generation',
};

// ============================================================================
// Repository Information
// ============================================================================

export interface RepoInfo {
  /** Path to checked-out repo (read-only for agents) */
  root: string;
  /** Original URL if cloned from remote */
  url?: string;
  /** Branch/tag/commit reference */
  ref: string;
  /** Resolved commit SHA */
  commit: string;
}

// ============================================================================
// Inventory Types (RepoIntakeAgent output)
// ============================================================================

export interface LanguageInfo {
  name: string;
  /** Percentage of codebase (0-1) */
  pct: number;
  /** Number of files */
  files: number;
}

export interface SecurityHotspot {
  path: string;
  reason: string;
  /** Line numbers if applicable */
  lines?: { start: number; end: number };
}

export interface RecommendedBackends {
  semgrep: boolean;
  codeql: { enabled: boolean; languages: string[] };
  joern: { enabled: boolean; languages: string[] };
  secrets: boolean;
  dependencies: boolean;
}

export interface RepoInventory {
  languages: LanguageInfo[];
  build_systems: string[];
  dependency_files: string[];
  security_hotspots: SecurityHotspot[];
  recommended_backends: RecommendedBackends;
  /** Estimated lines of code */
  total_loc?: number;
  /** Files to exclude from analysis */
  exclude_patterns: string[];
}

// ============================================================================
// Index Types (IndexGraphAgent output)
// ============================================================================

export interface SymbolInfo {
  name: string;
  kind: 'function' | 'class' | 'method' | 'variable' | 'constant' | 'type' | 'interface';
  path: string;
  line: number;
  exported: boolean;
  signature?: string;
}

export interface CallEdge {
  caller: { path: string; line: number; symbol: string };
  callee: { path: string; line: number; symbol: string };
}

export interface ImportEdge {
  importer: string;
  imported: string;
  symbols?: string[];
}

export interface CodeIndex {
  /** Path to symbols.json */
  symbol_index: string;
  /** Path to call_graph.json */
  call_graph: string;
  /** Path to import_graph.json */
  import_graph: string;
  /** Path to deps.json */
  dep_graph: string;
  /** Paths ranked by security relevance */
  hotspot_ranking: string[];
}

// ============================================================================
// Analysis Run Types (AnalyzerAgent output)
// ============================================================================

export type AnalysisTool = 'semgrep' | 'codeql' | 'joern' | 'secrets' | 'dependencies';

export interface AnalysisRun {
  tool: AnalysisTool;
  /** Path to output file */
  output: string;
  /** ISO timestamp */
  timestamp: string;
  /** Duration in milliseconds */
  duration_ms: number;
  /** Whether the run succeeded */
  success: boolean;
  /** Error message if failed */
  error?: string;
  /** Number of raw findings */
  raw_findings_count: number;
}

// ============================================================================
// Finding Types
// ============================================================================

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';
export type FindingStatus = 'candidate' | 'triaged' | 'confirmed' | 'rejected';

export interface RepoRef {
  path: string;
  start_line: number;
  end_line: number;
}

export interface TraceNode {
  path: string;
  line: number;
  symbol: string;
  snippet?: string;
}

export interface FindingTrace {
  sources: TraceNode[];
  sinks: TraceNode[];
  intermediate_nodes?: TraceNode[];
  path_summary: string;
  supporting_evidence: string[];
}

export interface FindingEvidence {
  type: 'tool_output' | 'code_excerpt' | 'custom_query';
  tool?: AnalysisTool;
  /** Path to evidence file */
  ref: string;
  /** Inline content for small evidence */
  content?: string;
}

export interface FindingRecommendation {
  fix_summary: string;
  safe_patterns: string[];
  notes: string;
  /** Example fix if available */
  example_fix?: string;
}

export interface FindingMetadata {
  tags: string[];
  created_by: StaticAnalysisStage;
  enriched_by: StaticAnalysisStage[];
  /** ISO timestamp */
  created_at: string;
  /** ISO timestamp */
  updated_at: string;
}

export interface StaticFinding {
  /** Stable hash-based ID */
  finding_id: string;
  title: string;
  description?: string;
  cwe: string[];
  severity: FindingSeverity;
  /** Confidence score 0.0-1.0 */
  confidence: number;
  status: FindingStatus;
  repo_refs: RepoRef[];
  trace: FindingTrace;
  evidence: FindingEvidence[];
  recommendation: FindingRecommendation;
  metadata: FindingMetadata;
  /** Reason for rejection if status is 'rejected' */
  rejection_reason?: string;
}

// ============================================================================
// State Contract (manifest.json)
// ============================================================================

export interface StaticAnalysisState {
  run_id: string;
  repo: RepoInfo;
  inventory?: RepoInventory;
  index?: CodeIndex;
  analysis_runs: AnalysisRun[];
  /** Paths to candidate finding files */
  candidates: string[];
  /** Paths to triaged finding files */
  findings: string[];
  report?: {
    sarif: string;
    md: string;
    json: string;
  };
  /** Current stage being executed */
  current_stage?: StaticAnalysisStage;
  /** Stages that have completed */
  completed_stages: StaticAnalysisStage[];
  /** ISO timestamp of run start */
  started_at: string;
  /** ISO timestamp of last update */
  updated_at: string;
  /** Error message if run failed */
  error?: string;
}

// ============================================================================
// Progress & Callback Types (matching web agent pattern)
// ============================================================================

export interface StaticAnalysisProgress {
  phase: StaticAnalysisStage | 'starting' | 'complete';
  message: string;
  currentStage?: number;
  totalStages: number;
  stagesCompleted?: number;
  findingsCount?: number;
  candidatesCount?: number;
  activeAgents?: number;
}

export interface StaticSubagentSpawnInfo {
  id: string;
  name: string;
  stage: StaticAnalysisStage;
  /** Stage number 1-8 */
  stageNumber: number;
}

export interface StaticSubagentStreamEvent {
  type: 'text-delta' | 'tool-call' | 'tool-result' | 'step-finish';
  agentId: string;
  data: {
    text?: string;
    toolCalls?: any[];
    toolResults?: any[];
    usage?: { promptTokens: number; completionTokens: number };
  };
}

export interface TokenUsage {
  /** Input/prompt tokens */
  inputTokens: number;
  /** Output/completion tokens */
  outputTokens: number;
  /** Total tokens (input + output) */
  totalTokens: number;
}

export interface StaticAgentResult {
  stage: StaticAnalysisStage;
  success: boolean;
  /** Paths to artifacts written */
  artifacts: string[];
  /** Summary message */
  summary: string;
  /** Error message if failed */
  error?: string;
  /** Duration in milliseconds */
  duration_ms: number;
  /** Token usage for this agent */
  tokenUsage?: TokenUsage;
}

// ============================================================================
// Orchestrator Input/Output (matching PentestOrchestratorInput/Result)
// ============================================================================

export interface StaticSessionConfig {
  /** Repository URL (if remote) */
  repoUrl?: string;
  /** Local repository path */
  repoPath?: string;
  /** Git ref to analyze */
  ref?: string;
  /** Languages to focus on (if empty, analyze all) */
  languages?: string[];
  /** Tools to skip (as string names to match Session.StaticConfig) */
  skipTools?: string[];
  /** Maximum findings to report */
  maxFindings?: number;
  /** Enable fast mode (skip heavy tools) */
  fastMode?: boolean;
}

export interface StaticOrchestratorInput {
  /** Local path to repository */
  repoPath: string;
  /** Remote URL if cloned */
  repoUrl?: string;
  /** Git ref to analyze */
  ref?: string;
  /** AI model to use */
  model: AIModel;
  /** Existing session (optional) */
  session?: Session.SessionInfo;
  /** Session configuration */
  sessionConfig?: StaticSessionConfig;
  /** Progress callback */
  onProgress?: (status: StaticAnalysisProgress) => void;
  /** Callback when a sub-agent is spawned */
  onAgentSpawn?: (info: StaticSubagentSpawnInfo) => void;
  /** Callback for stream events from sub-agents */
  onAgentStream?: (event: StaticSubagentStreamEvent) => void;
  /** Callback when a sub-agent completes */
  onAgentComplete?: (agentId: string, result: StaticAgentResult) => void;
  /** Abort signal */
  abortSignal?: AbortSignal;
  /** Maximum concurrent agents (default: 3) */
  concurrencyLimit?: number;
}

export interface StaticOrchestratorResult {
  session: Session.SessionInfo;
  state: StaticAnalysisState;
  findings: StaticFinding[];
  totalFindings: number;
  reportPaths: {
    sarif: string;
    md: string;
    json: string;
  };
  summary: string;
  /** Total duration in milliseconds */
  duration_ms: number;
  /** Total token usage across all agents */
  tokenUsage: TokenUsage;
  /** Token usage broken down by agent */
  tokenUsageByAgent: Record<StaticAnalysisStage, TokenUsage>;
}

// ============================================================================
// Tool Availability
// ============================================================================

export interface ToolAvailability {
  semgrep: { available: boolean; version?: string };
  codeql: { available: boolean; version?: string };
  joern: { available: boolean; version?: string };
  trufflehog: { available: boolean; version?: string };
  grype: { available: boolean; version?: string };
}

// ============================================================================
// Agent Timeouts
// ============================================================================

export const AGENT_TIMEOUTS: Record<StaticAnalysisStage, number> = {
  'repo-intake': 5 * 60 * 1000,      // 5 min
  'index-graph': 10 * 60 * 1000,     // 10 min
  'analyzer': 30 * 60 * 1000,        // 30 min (heavy)
  'spec-synth': 10 * 60 * 1000,      // 10 min
  'vul-rag': 5 * 60 * 1000,          // 5 min
  'localize': 15 * 60 * 1000,        // 15 min
  'triage': 5 * 60 * 1000,           // 5 min
  'exploit-synth': 20 * 60 * 1000,   // 20 min (POC gen + validation)
  'report': 5 * 60 * 1000,           // 5 min
};

// ============================================================================
// UI Types (matching swarm-dashboard)
// ============================================================================

export interface DisplayMessage {
  role: 'user' | 'assistant' | 'tool';
  content: string | object;
  toolName?: string;
  timestamp?: Date;
}

export interface StaticSubagent {
  id: string;
  name: string;
  type: StaticAnalysisStage;
  /** Stage number 1-8 */
  stage: number;
  messages: DisplayMessage[];
  createdAt: Date;
  status: 'pending' | 'completed' | 'failed';
  /** Artifacts produced */
  artifacts?: string[];
  /** Duration in milliseconds */
  duration_ms?: number;
}

// ============================================================================
// CWE Database Types (for VulRAG)
// ============================================================================

export interface CWEEntry {
  id: string;
  name: string;
  description: string;
  extended_description?: string;
  consequences: string[];
  mitigations: string[];
  detection_methods: string[];
  related_cwes: string[];
  common_languages: string[];
  severity_estimate: FindingSeverity;
}

export interface VulnerabilityPattern {
  id: string;
  cwe: string;
  language: string;
  pattern_type: 'source' | 'sink' | 'sanitizer' | 'propagator';
  description: string;
  code_pattern: string;
  /** Semgrep rule if available */
  semgrep_rule?: string;
}

// ============================================================================
// POC/Exploit Types (ExploitSynthAgent)
// ============================================================================

export type ExploitationPrimitive =
  | 'rce'              // Remote Code Execution
  | 'lfi'              // Local File Inclusion
  | 'rfi'              // Remote File Inclusion
  | 'sqli'             // SQL Injection
  | 'xss'              // Cross-Site Scripting
  | 'ssrf'             // Server-Side Request Forgery
  | 'xxe'              // XML External Entity
  | 'deserialize'      // Insecure Deserialization
  | 'path-traversal'   // Path Traversal
  | 'cmd-injection'    // OS Command Injection
  | 'info-disclosure'  // Information Disclosure
  | 'auth-bypass'      // Authentication Bypass
  | 'dos'              // Denial of Service
  | 'memory-corruption' // Memory Safety Issues
  | 'other';

export type POCValidationStatus =
  | 'not_attempted'    // POC not generated
  | 'generated'        // POC generated but not validated
  | 'validated'        // POC executed and confirmed vulnerability
  | 'failed'           // POC execution failed or did not trigger vuln
  | 'inconclusive';    // Could not determine if vuln was triggered

export interface POCFile {
  /** Filename (e.g., poc_sqli_001.py) */
  filename: string;
  /** Path to POC file in workspace */
  path: string;
  /** Language of the POC */
  language: string;
  /** POC source code */
  content: string;
  /** Setup instructions (dependencies, environment) */
  setup_instructions?: string;
  /** How to run the POC */
  execution_command: string;
  /** Expected output/behavior if vulnerability triggers */
  expected_result: string;
}

export interface POCExecutionResult {
  /** Whether the POC was executed */
  executed: boolean;
  /** Exit code if executed */
  exit_code?: number;
  /** stdout from execution */
  stdout?: string;
  /** stderr from execution */
  stderr?: string;
  /** Duration in milliseconds */
  duration_ms?: number;
  /** Whether the expected behavior was observed */
  vulnerability_triggered: boolean;
  /** Explanation of result */
  analysis: string;
}

export interface POCResult {
  /** Associated finding ID */
  finding_id: string;
  /** Exploitation primitive demonstrated */
  primitive: ExploitationPrimitive;
  /** Validation status */
  status: POCValidationStatus;
  /** Generated POC files */
  poc_files: POCFile[];
  /** Execution results if validated */
  execution_result?: POCExecutionResult;
  /** Why POC couldn't be generated (if applicable) */
  generation_failure_reason?: string;
  /** Risk assessment based on POC */
  risk_assessment: {
    /** Is this trivially exploitable? */
    trivially_exploitable: boolean;
    /** Does it require authentication? */
    requires_authentication: boolean;
    /** Does it require special conditions? */
    special_conditions?: string[];
    /** Real-world impact */
    impact_summary: string;
  };
  /** ISO timestamp */
  created_at: string;
}

/** Extended finding with POC information */
export interface ExploitableFinding extends StaticFinding {
  /** POC result if exploit synthesis was attempted */
  poc?: POCResult;
}
