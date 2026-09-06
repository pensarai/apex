import { z } from "zod";

export const EndpointScopeRecommendationSchema = z.object({
  category: z.enum([
    "health_probe",
    "static_asset",
    "documentation",
    "robots_sitemap",
    "other",
    "unknown",
  ]),
  excludeByDefault: z
    .boolean()
    .describe(
      "True only for a confirmed health/readiness/liveness probe, public static asset, " +
        "public documentation, robots file or sitemap with no concrete security-relevant behavior. " +
        "Metrics, diagnostics, other utilities and unknown behavior stay included. " +
        "Tenant-specific or sensitive output, authorization-sensitive files, user-controlled fetching, " +
        "and business operations stay included regardless of category. Consider ALL methods on the route. " +
        "A path name, low risk score, asset type or generic hypothetical vulnerability is not evidence.",
    ),
  reason: z
    .string()
    .trim()
    .min(1)
    .max(1000)
    .describe(
      "Brief evidence for the recommendation: cite source code in whitebox, or observed behavior / " +
        "supplied artifacts in blackbox. Do not invent observations. If evidence is insufficient, " +
        "choose unknown and excludeByDefault=false. This reason is shown to the user.",
    ),
});

export type EndpointScopeRecommendation = z.infer<
  typeof EndpointScopeRecommendationSchema
>;

export function endpointScopeDefaults(recommendation: unknown): {
  excludedFromScan: boolean;
  exclusionReason: string | null;
} {
  if (recommendation === undefined) {
    return { excludedFromScan: false, exclusionReason: null };
  }
  const parsed = EndpointScopeRecommendationSchema.parse(recommendation);
  if (
    parsed.excludeByDefault &&
    (parsed.category === "other" || parsed.category === "unknown")
  ) {
    throw new Error(
      `Cannot exclude endpoint category ${parsed.category} by default`,
    );
  }
  return {
    excludedFromScan: parsed.excludeByDefault,
    exclusionReason: parsed.excludeByDefault ? parsed.reason : null,
  };
}
