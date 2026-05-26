export const WHITEBOX_ARTIFACT_TYPES = [
  "repo-profile",
  "static-scan",
  "code-query",
  "source-trace",
  "candidate",
  "job-log",
  "fuzz-harness",
  "fuzz-crash",
  "build-log",
  "raw-output",
] as const;

export type WhiteboxArtifactType = (typeof WHITEBOX_ARTIFACT_TYPES)[number];

export type WhiteboxArtifactRef = {
  path: string;
  type: WhiteboxArtifactType;
  description: string;
};

export const WHITEBOX_CANDIDATE_STATES = [
  "hypothesis",
  "investigating",
  "repro_attempted",
  "confirmed",
  "rejected",
  "deferred",
] as const;

export type WhiteboxCandidateState = (typeof WHITEBOX_CANDIDATE_STATES)[number];

export type SourceLocation = {
  file: string;
  line?: number;
  symbol?: string;
};

export type SourceTrace = {
  source?: SourceLocation;
  sink?: SourceLocation;
  path?: SourceLocation[];
  notes?: string;
};

export type WhiteboxCandidate = {
  id: string;
  title: string;
  vulnerabilityClass: string;
  state: WhiteboxCandidateState;
  confidence: "low" | "medium" | "high";
  summary: string;
  sourceTrace?: SourceTrace;
  artifacts: WhiteboxArtifactRef[];
  verification?: {
    strategy: string;
    status: "not_started" | "running" | "failed" | "succeeded";
    notes?: string;
  };
  createdAt: string;
  updatedAt: string;
};

export type LanguageId =
  | "typescript"
  | "javascript"
  | "python"
  | "go"
  | "rust"
  | "java"
  | "kotlin"
  | "ruby"
  | "php"
  | "c"
  | "cpp"
  | "csharp"
  | "unknown";

export type PackageManagerId =
  | "bun"
  | "npm"
  | "yarn"
  | "pnpm"
  | "pip"
  | "poetry"
  | "cargo"
  | "go"
  | "maven"
  | "gradle"
  | "bundler"
  | "composer"
  | "dotnet";

export type ToolAvailability = {
  name: string;
  available: boolean;
  path?: string;
};

export type RepoProfile = {
  rootPath: string;
  currentCommit?: string;
  languages: LanguageId[];
  packageManagers: PackageManagerId[];
  manifestFiles: string[];
  lockfiles: string[];
  buildCommands: string[];
  testCommands: string[];
  runCommands: string[];
  entryPointHints: string[];
  iacFiles: string[];
  ciFiles: string[];
  nativeCode: boolean;
  submodules: string[];
  excludedDirs: string[];
  toolAvailability: ToolAvailability[];
};

export type CatalogRecordKind =
  | "entry-point"
  | "trust-boundary"
  | "sink"
  | "scanner"
  | "fuzzer"
  | "review-pass"
  | "verification";

export type CatalogRecord = {
  id: string;
  kind: CatalogRecordKind;
  title: string;
  languages?: LanguageId[];
  tags: string[];
  patterns?: string[];
  tools?: string[];
  guidance: string;
};

export type CatalogSelection = {
  records: CatalogRecord[];
  recommendedPasses: CatalogRecord[];
};

export type ScanKind =
  | "static"
  | "secrets"
  | "dependencies"
  | "iac"
  | "repo-intelligence"
  | "fuzzing";

export type ScanFindingSummary = {
  tool: string;
  severity?: string;
  title: string;
  location?: SourceLocation;
  description?: string;
};

export type ScanRunResult = {
  scanner: string;
  command: string[];
  exitCode: number | null;
  findings: ScanFindingSummary[];
  artifact: WhiteboxArtifactRef;
  /** True when stdout/stderr capture hit the byte cap before the process ended. */
  outputTruncated?: boolean;
  /** True when the scanner hit the wall-clock timeout (exit code 124). */
  timedOut?: boolean;
};

export type WhiteboxJobStatus =
  | "running"
  | "completed"
  | "failed"
  | "timed_out"
  | "stopped";

export type WhiteboxJobRecord = {
  id: string;
  command: string;
  cwd: string;
  logPath: string;
  startedAt: string;
  updatedAt: string;
  timeoutSeconds: number;
  status: WhiteboxJobStatus;
  exitCode?: number | null;
};
