import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { awsLookup } from "./awsLookup";
import { gcpLookup } from "./gcpLookup";
import type { CloudLookupResult } from "./types";

/**
 * Factory for the `cloud_resource_lookup` tool.
 *
 * Resolves a cloud resource reference (found in code, config, or
 * during recon) to its actual domain / URL / IP. Used during
 * whitebox-recon and attack surface discovery so the agent can
 * correctly set domains on `document_app` / `document_endpoint` calls.
 */
export function cloudResourceLookup(ctx: ToolContext) {
  const providers = ctx.session.config?.cloudProviders?.providers ?? [];
  const hasProviders = providers.length > 0;

  return tool({
    description: `Look up a cloud resource to resolve its actual URL, domain, or IP address.

Use this when you find a reference to a cloud resource in code, config files, or infrastructure definitions and need to determine the actual domain or URL it resolves to. This is essential for correctly documenting endpoints and applications during reconnaissance.

**When to use:**
- Found a Lambda function name in code → look up its function URL
- Found an S3 bucket name → resolve its website/regional endpoint
- Found a CloudFront distribution ID → get the d*.cloudfront.net domain
- Found an API Gateway name → resolve the execute-api.amazonaws.com URL
- Found a Cloud Run service name → resolve its *.run.app URL
- Found a load balancer name → get its DNS name or IP
- Found a GCS bucket reference → resolve its storage URL
- Found a domain in code → check Route53/Cloud DNS for the actual target

**AWS resource types:** lambda, s3, cloudfront, apigateway, elb, alb, nlb, ecs, rds, route53, ec2
**GCP resource types:** cloudrun, cloudfunction, gcs, appengine, gke, cloudsql, loadbalancer, clouddns

${hasProviders ? `Available providers: ${providers.map((p) => `${p.name} (${p.provider})`).join(", ")}` : "No cloud providers configured. Ask the user to add cloud provider credentials in Pensar Console settings."}`,
    inputSchema: z.object({
      resourceType: z
        .string()
        .describe(
          "The type of cloud resource to look up (e.g., 'lambda', 's3', 'cloudfront', 'cloudrun', 'gcs')",
        ),
      identifier: z
        .string()
        .describe(
          "The resource name, ID, ARN, or domain to look up (e.g., 'my-function', 'my-bucket', 'd111111abcdef8')",
        ),
      provider: z
        .enum(["aws", "gcp"])
        .optional()
        .describe(
          "Which cloud provider to query. If omitted, inferred from the resource type or queries all configured providers.",
        ),
      region: z
        .string()
        .optional()
        .describe(
          "Override the default region for this lookup (e.g., 'us-west-2', 'europe-west1')",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Resolving Lambda function URL for auth-service')",
        ),
    }),
    execute: async ({
      resourceType,
      identifier,
      provider,
      region,
    }): Promise<CloudLookupResult> => {
      if (!hasProviders) {
        return {
          success: false,
          provider: provider ?? "unknown",
          resources: [],
          error:
            "No cloud providers configured. Cloud provider credentials must be added in Pensar Console → Settings → Integrations → Cloud Providers.",
        };
      }

      const AWS_TYPES = new Set([
        "lambda",
        "s3",
        "cloudfront",
        "apigateway",
        "elb",
        "alb",
        "nlb",
        "ecs",
        "rds",
        "route53",
        "ec2",
      ]);
      const GCP_TYPES = new Set([
        "cloudrun",
        "cloudfunction",
        "gcs",
        "appengine",
        "gke",
        "cloudsql",
        "loadbalancer",
        "clouddns",
      ]);

      const normalizedType = resourceType
        .toLowerCase()
        .replace(/[-_ ]/g, "");

      // Determine which providers to query
      let targetProvider = provider;
      if (!targetProvider) {
        if (AWS_TYPES.has(normalizedType)) targetProvider = "aws";
        else if (GCP_TYPES.has(normalizedType)) targetProvider = "gcp";
      }

      const matchingProviders = providers.filter(
        (p) => !targetProvider || p.provider === targetProvider,
      );

      if (matchingProviders.length === 0) {
        return {
          success: false,
          provider: targetProvider ?? "unknown",
          resources: [],
          error: `No ${targetProvider ?? ""} cloud provider configured. Available: ${providers.map((p) => `${p.name} (${p.provider})`).join(", ")}`,
        };
      }

      const allResults: CloudLookupResult[] = [];

      for (const providerConfig of matchingProviders) {
        if (providerConfig.provider === "aws") {
          const result = await awsLookup(
            resourceType,
            identifier,
            {
              accessKeyId: providerConfig.accessKeyId,
              secretAccessKey: providerConfig.secretAccessKey,
              region: region ?? providerConfig.region,
            },
            region,
          );
          allResults.push(result);
        } else if (providerConfig.provider === "gcp") {
          const result = await gcpLookup(
            resourceType,
            identifier,
            {
              projectId: providerConfig.projectId,
              serviceAccountKey: providerConfig.serviceAccountKey,
            },
            region,
          );
          allResults.push(result);
        }
      }

      const mergedResources = allResults.flatMap((r) => r.resources);
      const errors = allResults
        .filter((r) => !r.success && r.error)
        .map((r) => r.error!);

      if (mergedResources.length > 0) {
        return {
          success: true,
          provider: targetProvider ?? "multi",
          resources: mergedResources,
        };
      }

      return {
        success: false,
        provider: targetProvider ?? "multi",
        resources: [],
        error:
          errors.length > 0
            ? errors.join("; ")
            : `No resources found for ${resourceType}/${identifier}`,
      };
    },
  });
}
