import { z } from "zod";

export const WHITEBOX_RECON_SCHEMA = "whitebox-recon/v2" as const;
export const WHITEBOX_RECON_PIPELINE_VERSION = "selector-map-reduce/v5";

export type InventoryFileKind =
  | "source"
  | "manifest"
  | "build"
  | "container"
  | "infrastructure"
  | "api-spec"
  | "schema"
  | "config"
  | "documentation"
  | "test"
  | "other";
export type InventoryRelevance = "analyze" | "excluded" | "unresolved";

export interface InventoryFile {
  path: string;
  size_bytes: number;
  line_count?: number;
  sha256?: string;
  kind: InventoryFileKind;
  language?: string;
  relevance: InventoryRelevance;
  reason?: string;
  high_signal: boolean;
}

export interface InventoryDirectoryExclusion {
  path: string;
  reason: string;
}

export interface RepositoryInventory {
  repository_root: string;
  files: InventoryFile[];
  excluded_directories: InventoryDirectoryExclusion[];
}

export interface ReconApplication {
  id: string;
  name: string;
  source_roots: string[];
  languages: string[];
  frameworks: string[];
  domains: string[];
}

export type SurfaceType = "http" | "graphql" | "grpc" | "network";

export interface ReconSurface {
  application_id: string;
  type: SurfaceType;
  method?: string;
  path_or_name: string;
  source_file: string;
  source_line: number;
  handler_file?: string;
  handler_line?: number;
}

export type ResourceType =
  | "database"
  | "queue"
  | "cache"
  | "bucket"
  | "service"
  | "other";

export interface ReconResource {
  application_id: string;
  type: ResourceType;
  provider: string;
  identifier: string;
  source_file: string;
  source_line?: number;
}

export type CandidateDisposition =
  | "accepted"
  | "duplicate"
  | "rejected"
  | "unresolved";

export interface ApplicationCandidate extends ReconApplication {
  disposition: CandidateDisposition;
  disposition_reason?: string;
  candidate_ids: string[];
}

export interface SurfaceCandidate extends ReconSurface {
  candidate_id: string;
  disposition: CandidateDisposition;
  disposition_reason?: string;
}

export interface ResourceCandidate extends ReconResource {
  candidate_id: string;
  disposition: CandidateDisposition;
  disposition_reason?: string;
}

export type UnresolvedKind =
  | "application"
  | "application-assignment"
  | "surface"
  | "resource"
  | "relationship"
  | "candidate"
  | "selector"
  | "batch"
  | "conflict"
  | "model-failure"
  | "inventory"
  | "budget";

export interface UnresolvedItem {
  kind: UnresolvedKind;
  summary: string;
  source_files: string[];
  reason: string;
}

export type SelectorCategory =
  | "application"
  | "http"
  | "graphql"
  | "grpc"
  | "network"
  | "resource";

export interface LiteralSelector {
  id: string;
  category: SelectorCategory;
  description: string;
  literals: string[];
  match: "any" | "all";
  case_sensitive: boolean;
  extensions: string[];
  path_contains: string[];
}

export interface PlannerResult {
  applications: ApplicationCandidate[];
  selectors: LiteralSelector[];
  configuration_ownership: ConfigOwnershipRule[];
  unresolved: UnresolvedItem[];
}

export interface ConfigOwnershipRule {
  path_prefix: string;
  application_id: string;
  reason: string;
}

export interface ReconSelector {
  id: string;
  category: SelectorCategory;
  description: string;
  source: "builtin" | "planner";
  kind: "builtin" | "literal";
  literal?: LiteralSelector;
}

export interface ReconCandidate {
  id: string;
  selector_ids: string[];
  categories: SelectorCategory[];
  path: string;
  line_start: number;
  line_end: number;
  snippet: string;
  dependency_context: DependencyContext[];
}

export interface DependencyContext {
  source_line: number;
  statement: string;
  resolved_path: string;
}

export interface FileScan {
  path: string;
  status: "no-signal" | "candidate" | "unresolved";
  candidate_ids: string[];
  reason?: string;
}

export interface CandidateLedger {
  selectors: ReconSelector[];
  candidates: ReconCandidate[];
  files: FileScan[];
  errors: UnresolvedItem[];
}

export interface EvidenceBundle {
  id: string;
  application_ids: string[];
  locality: string;
  candidates: ReconCandidate[];
}

export interface CandidateReview {
  candidate_id: string;
  disposition: CandidateDisposition;
  reason?: string;
}

export interface WorkerResult {
  bundle_id: string;
  applications: ApplicationCandidate[];
  surfaces: SurfaceCandidate[];
  resources: ResourceCandidate[];
  candidate_reviews: CandidateReview[];
  unresolved: UnresolvedItem[];
}

export interface ApplicationUpdate {
  application_id: string;
  name?: string;
  source_roots?: string[];
  languages?: string[];
  frameworks?: string[];
  domains?: string[];
  reason: string;
}

export interface ReconciliationResult {
  application_merges: Array<{
    source_application_id: string;
    target_application_id: string;
    reason: string;
  }>;
  application_updates: ApplicationUpdate[];
  surface_reassignments: Array<{
    observation_id: string;
    application_id: string;
    reason: string;
  }>;
  resource_reassignments: Array<{
    observation_id: string;
    application_id: string;
    reason: string;
  }>;
  surface_dispositions: Array<{
    observation_id: string;
    disposition: "duplicate" | "rejected" | "unresolved";
    reason: string;
  }>;
  resource_dispositions: Array<{
    observation_id: string;
    disposition: "duplicate" | "rejected" | "unresolved";
    reason: string;
  }>;
  unresolved: UnresolvedItem[];
}

export interface ModelUsage {
  input_tokens: number;
  output_tokens: number;
}

export interface ModelResult<TResult> {
  result: TResult;
  usage: ModelUsage;
}

export interface ReconMetrics {
  duration_ms: number;
  files_total: number;
  files_relevant: number;
  files_reviewed: number;
  selectors_total: number;
  selectors_completed: number;
  shards_total: number;
  shards_completed: number;
  bundle_cache_hits: number;
  candidates_total: number;
  candidates_accepted: number;
  candidates_persisted: number;
  candidates_duplicate: number;
  candidates_rejected: number;
  candidates_unresolved: number;
  records_accepted: number;
  records_persisted: number;
  agent_calls: number;
  agent_failures: number;
  tokens_in: number;
  tokens_out: number;
  estimated_tokens_in: number;
}

export interface WhiteboxReconResult {
  $schema: typeof WHITEBOX_RECON_SCHEMA;
  status: "complete" | "incomplete";
  repository_root: string;
  applications: ReconApplication[];
  surfaces: ReconSurface[];
  resources: ReconResource[];
  unresolved: UnresolvedItem[];
  metrics: ReconMetrics;
}

export const InventoryFileKindSchema = z.enum([
  "source",
  "manifest",
  "build",
  "container",
  "infrastructure",
  "api-spec",
  "schema",
  "config",
  "documentation",
  "test",
  "other",
]);
export const InventoryRelevanceSchema = z.enum([
  "analyze",
  "excluded",
  "unresolved",
]);
const InventoryFileObjectSchema = z.object({
  path: z.string().min(1),
  size_bytes: z.number().int().nonnegative(),
  line_count: z.number().int().positive().optional(),
  sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
  kind: InventoryFileKindSchema,
  language: z.string().optional(),
  relevance: InventoryRelevanceSchema,
  reason: z.string().optional(),
  high_signal: z.boolean(),
});
export const InventoryFileSchema: z.ZodType<InventoryFile> =
  InventoryFileObjectSchema;
export const InventoryDirectoryExclusionSchema: z.ZodType<InventoryDirectoryExclusion> =
  z.object({ path: z.string().min(1), reason: z.string().min(1) });
export const RepositoryInventorySchema: z.ZodType<RepositoryInventory> =
  z.object({
    repository_root: z.string().min(1),
    files: z.array(InventoryFileSchema),
    excluded_directories: z.array(InventoryDirectoryExclusionSchema),
  });

const ApplicationObjectSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  source_roots: z.array(z.string()),
  languages: z.array(z.string()),
  frameworks: z.array(z.string()),
  domains: z.array(z.string()),
});
export const ApplicationSchema: z.ZodType<ReconApplication> =
  ApplicationObjectSchema;
export const SurfaceTypeSchema = z.enum(["http", "graphql", "grpc", "network"]);
const SurfaceObjectSchema = z.object({
  application_id: z.string().min(1),
  type: SurfaceTypeSchema,
  method: z.string().optional(),
  path_or_name: z.string().min(1),
  source_file: z.string().min(1),
  source_line: z.number().int().nonnegative(),
  handler_file: z.string().min(1).optional(),
  handler_line: z.number().int().nonnegative().optional(),
});
export const SurfaceSchema: z.ZodType<ReconSurface> = SurfaceObjectSchema;
export const ResourceTypeSchema = z.enum([
  "database",
  "queue",
  "cache",
  "bucket",
  "service",
  "other",
]);
const ResourceObjectSchema = z.object({
  application_id: z.string().min(1),
  type: ResourceTypeSchema,
  provider: z.string().min(1),
  identifier: z.string().min(1),
  source_file: z.string().min(1),
  source_line: z.number().int().nonnegative().optional(),
});
export const ResourceSchema: z.ZodType<ReconResource> = ResourceObjectSchema;
export const CandidateDispositionSchema = z.enum([
  "accepted",
  "duplicate",
  "rejected",
  "unresolved",
]);
const ApplicationCandidateObjectSchema = ApplicationObjectSchema.extend({
  disposition: CandidateDispositionSchema,
  disposition_reason: z.string().optional(),
  candidate_ids: z.array(z.string().min(1)),
});
export const ApplicationCandidateSchema: z.ZodType<ApplicationCandidate> =
  ApplicationCandidateObjectSchema;
export const SurfaceCandidateSchema: z.ZodType<SurfaceCandidate> =
  SurfaceObjectSchema.extend({
    candidate_id: z.string().min(1),
    disposition: CandidateDispositionSchema,
    disposition_reason: z.string().optional(),
  });
export const ResourceCandidateSchema: z.ZodType<ResourceCandidate> =
  ResourceObjectSchema.extend({
    candidate_id: z.string().min(1),
    disposition: CandidateDispositionSchema,
    disposition_reason: z.string().optional(),
  });
export const UnresolvedItemSchema: z.ZodType<UnresolvedItem> = z.object({
  kind: z.enum([
    "application",
    "application-assignment",
    "surface",
    "resource",
    "relationship",
    "candidate",
    "selector",
    "batch",
    "conflict",
    "model-failure",
    "inventory",
    "budget",
  ]),
  summary: z.string().min(1),
  source_files: z.array(z.string()),
  reason: z.string().min(1),
});
export const SelectorCategorySchema = z.enum([
  "application",
  "http",
  "graphql",
  "grpc",
  "network",
  "resource",
]);
export const LiteralSelectorSchema: z.ZodType<LiteralSelector> = z.object({
  id: z.string().min(1).max(80),
  category: SelectorCategorySchema,
  description: z.string().min(1).max(240),
  literals: z.array(z.string().min(2).max(120)).min(1).max(16),
  match: z.enum(["any", "all"]),
  case_sensitive: z.boolean(),
  extensions: z.array(z.string().max(16)).max(24),
  path_contains: z.array(z.string().min(1).max(120)).max(16),
});
export const PlannerResultSchema: z.ZodType<PlannerResult> = z.object({
  applications: z.array(ApplicationCandidateSchema).max(500),
  selectors: z.array(LiteralSelectorSchema).max(40),
  configuration_ownership: z
    .array(
      z.object({
        path_prefix: z.string().min(1).max(500),
        application_id: z.string().min(1),
        reason: z.string().min(1).max(500),
      }),
    )
    .max(500),
  unresolved: z.array(UnresolvedItemSchema).max(500),
});
export const ReconSelectorSchema: z.ZodType<ReconSelector> = z.object({
  id: z.string().min(1),
  category: SelectorCategorySchema,
  description: z.string().min(1),
  source: z.enum(["builtin", "planner"]),
  kind: z.enum(["builtin", "literal"]),
  literal: LiteralSelectorSchema.optional(),
});
export const ReconCandidateSchema: z.ZodType<ReconCandidate> = z.object({
  id: z.string().min(1),
  selector_ids: z.array(z.string().min(1)).min(1),
  categories: z.array(SelectorCategorySchema).min(1),
  path: z.string().min(1),
  line_start: z.number().int().positive(),
  line_end: z.number().int().positive(),
  snippet: z.string().min(1),
  dependency_context: z.array(
    z.object({
      source_line: z.number().int().positive(),
      statement: z.string().min(1),
      resolved_path: z.string().min(1),
    }),
  ),
});
export const FileScanSchema: z.ZodType<FileScan> = z.object({
  path: z.string().min(1),
  status: z.enum(["no-signal", "candidate", "unresolved"]),
  candidate_ids: z.array(z.string()),
  reason: z.string().optional(),
});
export const CandidateLedgerSchema: z.ZodType<CandidateLedger> = z.object({
  selectors: z.array(ReconSelectorSchema),
  candidates: z.array(ReconCandidateSchema),
  files: z.array(FileScanSchema),
  errors: z.array(UnresolvedItemSchema),
});
export const EvidenceBundleSchema: z.ZodType<EvidenceBundle> = z.object({
  id: z.string().min(1),
  application_ids: z.array(z.string()),
  locality: z.string().min(1),
  candidates: z.array(ReconCandidateSchema).min(1),
});
export const CandidateReviewSchema: z.ZodType<CandidateReview> = z.object({
  candidate_id: z.string().min(1),
  disposition: CandidateDispositionSchema,
  reason: z.string().min(1).optional(),
});
export const WorkerResultSchema: z.ZodType<WorkerResult> = z.object({
  bundle_id: z.string().min(1),
  applications: z.array(ApplicationCandidateSchema),
  surfaces: z.array(SurfaceCandidateSchema),
  resources: z.array(ResourceCandidateSchema),
  candidate_reviews: z.array(CandidateReviewSchema),
  unresolved: z.array(UnresolvedItemSchema),
});
export const ApplicationUpdateSchema: z.ZodType<ApplicationUpdate> = z.object({
  application_id: z.string().min(1),
  name: z.string().min(1).optional(),
  source_roots: z.array(z.string()).optional(),
  languages: z.array(z.string()).optional(),
  frameworks: z.array(z.string()).optional(),
  domains: z.array(z.string()).optional(),
  reason: z.string().min(1),
});
export const ReconciliationResultSchema: z.ZodType<ReconciliationResult> =
  z.object({
    application_merges: z.array(
      z.object({
        source_application_id: z.string().min(1),
        target_application_id: z.string().min(1),
        reason: z.string().min(1),
      }),
    ),
    application_updates: z.array(ApplicationUpdateSchema),
    surface_reassignments: z.array(
      z.object({
        observation_id: z.string().min(1),
        application_id: z.string().min(1),
        reason: z.string().min(1),
      }),
    ),
    resource_reassignments: z.array(
      z.object({
        observation_id: z.string().min(1),
        application_id: z.string().min(1),
        reason: z.string().min(1),
      }),
    ),
    surface_dispositions: z.array(
      z.object({
        observation_id: z.string().min(1),
        disposition: z.enum(["duplicate", "rejected", "unresolved"]),
        reason: z.string().min(1),
      }),
    ),
    resource_dispositions: z.array(
      z.object({
        observation_id: z.string().min(1),
        disposition: z.enum(["duplicate", "rejected", "unresolved"]),
        reason: z.string().min(1),
      }),
    ),
    unresolved: z.array(UnresolvedItemSchema),
  });
export const ReconMetricsSchema: z.ZodType<ReconMetrics> = z.object({
  duration_ms: z.number().int().nonnegative(),
  files_total: z.number().int().nonnegative(),
  files_relevant: z.number().int().nonnegative(),
  files_reviewed: z.number().int().nonnegative(),
  selectors_total: z.number().int().nonnegative(),
  selectors_completed: z.number().int().nonnegative(),
  shards_total: z.number().int().nonnegative(),
  shards_completed: z.number().int().nonnegative(),
  bundle_cache_hits: z.number().int().nonnegative(),
  candidates_total: z.number().int().nonnegative(),
  candidates_accepted: z.number().int().nonnegative(),
  candidates_persisted: z.number().int().nonnegative(),
  candidates_duplicate: z.number().int().nonnegative(),
  candidates_rejected: z.number().int().nonnegative(),
  candidates_unresolved: z.number().int().nonnegative(),
  records_accepted: z.number().int().nonnegative(),
  records_persisted: z.number().int().nonnegative(),
  agent_calls: z.number().int().nonnegative(),
  agent_failures: z.number().int().nonnegative(),
  tokens_in: z.number().int().nonnegative(),
  tokens_out: z.number().int().nonnegative(),
  estimated_tokens_in: z.number().int().nonnegative(),
});
export const WhiteboxReconResultSchema: z.ZodType<WhiteboxReconResult> =
  z.object({
    $schema: z.literal(WHITEBOX_RECON_SCHEMA),
    status: z.enum(["complete", "incomplete"]),
    repository_root: z.string().min(1),
    applications: z.array(ApplicationSchema),
    surfaces: z.array(SurfaceSchema),
    resources: z.array(ResourceSchema),
    unresolved: z.array(UnresolvedItemSchema),
    metrics: ReconMetricsSchema,
  });
