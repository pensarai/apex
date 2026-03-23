import { tool } from "ai";
import { z } from "zod";

/**
 * Factory for the `validate_discovery_completeness` tool.
 *
 * Evaluates recon coverage, computes a confidence score, and
 * identifies gaps before the final report is generated.
 */
export function validateDiscovery(_ctx: unknown) {
  return tool({
    description:
      "Check discovery completeness. Returns confidence score and identifies gaps in auth, JS analysis, and endpoint coverage.",
    inputSchema: z.object({
      discoveredEndpoints: z
        .array(z.string())
        .describe("All discovered endpoints"),
      authenticatedWithCredentials: z
        .boolean()
        .describe("Whether you authenticated with any discovered credentials"),
      pagesWithJSAnalyzed: z
        .array(z.string())
        .describe("Pages where you ran extract_js_endpoints"),
      credentialsFound: z
        .boolean()
        .describe("Whether any credentials were discovered"),
    }),
    execute: async (params) => {
      const {
        discoveredEndpoints,
        authenticatedWithCredentials,
        pagesWithJSAnalyzed,
        credentialsFound,
      } = params;

      const gaps: Array<{
        gap: string;
        severity: string;
        recommendation: string;
      }> = [];
      let confidence = 100;

      // Check: Authenticated if credentials found
      if (credentialsFound && !authenticatedWithCredentials) {
        gaps.push({
          gap: "Credentials found but never used for authentication",
          severity: "CRITICAL",
          recommendation:
            "Use authenticate_session with discovered credentials, then use crawl_authenticated_area to explore authenticated sections",
        });
        confidence -= 40;
      }

      // Check: JavaScript analysis on authenticated pages
      if (authenticatedWithCredentials && pagesWithJSAnalyzed.length === 0) {
        gaps.push({
          gap: "Authenticated but no JavaScript analysis performed",
          severity: "CRITICAL",
          recommendation:
            "Use extract_js_endpoints on /dashboard, /orders, and other authenticated pages",
        });
        confidence -= 30;
      }

      // Check: CRUD enumeration for resource patterns
      const resourcePatterns = discoveredEndpoints.filter((ep) =>
        ep.includes("{id}"),
      );
      if (
        resourcePatterns.length > 0 &&
        !discoveredEndpoints.some(
          (ep) => ep.includes("receipt") || ep.includes("archive"),
        )
      ) {
        gaps.push({
          gap: "Resource patterns found but CRUD operations not enumerated",
          severity: "HIGH",
          recommendation:
            "Test all CRUD variations (receipt, archive, delete, edit, etc.)",
        });
        confidence -= 20;
      }

      // Check: Minimum endpoint discovery
      if (discoveredEndpoints.length < 5) {
        gaps.push({
          gap: "Very few endpoints discovered (less than 5)",
          severity: "MEDIUM",
          recommendation:
            "Ensure you crawled authenticated areas, analyzed JavaScript, and tested common paths",
        });
        confidence -= 10;
      }

      const complete = confidence >= 90;

      return {
        complete,
        confidence,
        gaps,
        summary: complete
          ? `Discovery is ${confidence}% complete. Ready to generate final report.`
          : `Discovery is only ${confidence}% complete. ${gaps.length} critical gaps found.`,
        readyForReport: complete,
        message: complete
          ? "Validation passed. You can now call create_attack_surface_report."
          : `Validation failed. Address these gaps before reporting: ${gaps
              .map((g) => g.gap)
              .join("; ")}`,
      };
    },
  });
}
