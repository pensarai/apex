/**
 * Pentest Workflow API
 *
 * Public API for running penetration tests from the console application.
 *
 * @example
 * ```typescript
 * import { runWhiteboxPentest, runBlackboxPentest, resumePentest } from '@pensar/apex/api';
 *
 * // Whitebox pentest (single endpoint with source code)
 * const result = await runWhiteboxPentest({
 *   endpoint: 'http://localhost:3000/api/users',
 *   sourceCodePath: '/path/to/source',
 *   callbacks: {
 *     onFindingDiscovered: (finding) => console.log('Found:', finding.title),
 *   },
 * });
 *
 * // Blackbox pentest (full domain scan)
 * const result = await runBlackboxPentest({
 *   target: 'https://example.com',
 *   callbacks: {
 *     onPhaseChange: (phase) => console.log('Phase:', phase),
 *     onSubagentStart: (id, endpoint, vulnClass) => console.log('Testing:', vulnClass),
 *   },
 * });
 *
 * // Resume an interrupted session
 * const result = await resumePentest({
 *   sessionId: 'pentest-ses_abc123',
 * });
 * ```
 */

// Main API functions
export { runWhiteboxPentest, runBlackboxPentest, resumePentest } from "./pentest";


// Type exports
export type {
  // Input types
  WhiteboxPentestInput,
  BlackboxPentestInput,
  ResumePentestInput,
  PentestCallbacks,
  ToolOverride,
  // Output types
  PentestResult,
  PentestStats,
  // State types
  SessionState,
  SessionPhase,
  // Re-exported core types
  AIModel,
  Finding,
  VulnerabilityClass,
  SubAgentManifest,
  FileAccessConfig,
  RunSubAgentResult,
  AuthCredentials,
  ScopeConstraints,
  SessionConfig,
} from "./types";
