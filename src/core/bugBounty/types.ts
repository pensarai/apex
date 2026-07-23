import { z } from "zod";

export const BugBountyPlatformSchema = z.enum([
  "hackerone",
  "bugcrowd",
  "intigriti",
  "generic",
]);

export const BugBountyAssetTypeSchema = z.enum([
  "url",
  "domain",
  "wildcard",
  "ip",
  "cidr",
  "repository",
  "mobile",
  "other",
]);

export const BugBountyAssetSchema = z.object({
  value: z.string().min(1),
  type: BugBountyAssetTypeSchema,
  inScope: z.boolean(),
  instructions: z.string().optional(),
  sourceExcerpt: z.string().min(1),
});

export const BugBountyRuleSchema = z.object({
  category: z.enum([
    "authorization",
    "rate-limit",
    "testing-window",
    "prohibited-action",
    "submission",
    "other",
  ]),
  statement: z.string().min(1),
  sourceExcerpt: z.string().min(1),
});

export const RequiredHeaderSchema = z.object({
  name: z.string().min(1),
  value: z.string().optional(),
  sourceExcerpt: z.string().min(1),
});

export const BugBountyBriefSchema = z.object({
  programName: z.string().min(1),
  platform: BugBountyPlatformSchema,
  status: z.enum(["open", "closed", "unknown"]),
  source: z.object({
    listingUrl: z.string().url(),
    fetchedAt: z.string().datetime(),
    contentHash: z.string().regex(/^[a-f0-9]{64}$/),
  }),
  assets: z.array(BugBountyAssetSchema),
  rules: z.array(BugBountyRuleSchema),
  requiredHeaders: z.array(RequiredHeaderSchema),
  notes: z.array(z.string()),
  ambiguities: z.array(z.string()),
});

export const EngagementPolicySchema = z.object({
  version: z.literal("1"),
  policyHash: z.string().regex(/^[a-f0-9]{64}$/),
  listingUrl: z.string().url(),
  listingContentHash: z.string().regex(/^[a-f0-9]{64}$/),
  platform: BugBountyPlatformSchema,
  programName: z.string(),
  allowedTargets: z.array(BugBountyAssetSchema),
  excludedTargets: z.array(BugBountyAssetSchema),
  allowedHosts: z.array(z.string()),
  requiredHeaders: z.record(z.string(), z.string()),
  requestsPerSecond: z.number().positive().optional(),
  rules: z.array(BugBountyRuleSchema),
  guidance: z.string(),
  blockers: z.array(z.string()),
  canExecute: z.boolean(),
});

export type BugBountyPlatform = z.infer<typeof BugBountyPlatformSchema>;
export type BugBountyAsset = z.infer<typeof BugBountyAssetSchema>;
export type BugBountyRule = z.infer<typeof BugBountyRuleSchema>;
export type RequiredHeader = z.infer<typeof RequiredHeaderSchema>;
export type BugBountyBrief = z.infer<typeof BugBountyBriefSchema>;
export type EngagementPolicy = z.infer<typeof EngagementPolicySchema>;

export interface AnalyzeBugBountyListingInput {
  listingUrl: string;
  /** Pre-fetched public or authenticated listing content. */
  content?: string;
  fetchImpl?: typeof fetch;
  resolveHostname?: (hostname: string) => Promise<string[]>;
  abortSignal?: AbortSignal;
}

export interface CompileEngagementPolicyOptions {
  /** Session/workspace headers used to resolve header names without literals. */
  configuredHeaders?: Record<string, string>;
}
