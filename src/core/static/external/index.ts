/**
 * External Tool Integrations
 *
 * Wrappers for external static analysis tools.
 */

// Tool availability detection
export * from './detector';

// Semgrep integration
export * from './semgrep';

// CodeQL integration
export * from './codeql';

// Joern integration
export * from './joern';

// TruffleHog secrets scanning
export * from './trufflehog';

// Re-export commonly used functions
export {
  detectAvailableTools,
  hasMinimumTools,
  getToolSummary,
  getInstallInstructions,
} from './detector';

export { runSemgrep, mapSemgrepSeverity, extractCWEs } from './semgrep';

export {
  runCodeQL,
  createCodeQLDatabase,
  runCodeQLQueries,
  mapCodeQLSeverity,
  CODEQL_LANGUAGES,
} from './codeql';

export {
  runJoern,
  createJoernCPG,
  runJoernQueries,
  mapJoernSeverity,
  generateTaintQuery,
  JOERN_LANGUAGES,
} from './joern';

export {
  runTrufflehog,
  runTrufflehogGit,
  getSecretSeverity,
  getSecretCWE,
  getSecretLocation,
} from './trufflehog';
