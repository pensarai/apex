import { tool } from "ai";
import { z } from "zod";
import {
  type DocumentEndpointInput,
  documentEndpoint,
  documentEndpointInputSchema,
} from "./documentEndpoint";
import type { ToolContext } from "./types";

export const DOCUMENT_ENDPOINT_BATCH_SIZE = 4;

const batchEndpointSchema = documentEndpointInputSchema.omit({
  toolCallDescription: true,
});

export const documentEndpointsInputSchema = z.object({
  endpoints: z
    .array(batchEndpointSchema)
    .min(1)
    .max(DOCUMENT_ENDPOINT_BATCH_SIZE)
    .describe(
      `One bounded batch of at most ${DOCUMENT_ENDPOINT_BATCH_SIZE} endpoints.`,
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of the endpoint batch being documented",
    ),
});

type DocumentEndpointsInput = z.infer<typeof documentEndpointsInputSchema>;

export function documentEndpoints(ctx: ToolContext) {
  const endpointTool = documentEndpoint(ctx);

  return tool({
    description: `Document and threat-model a bounded endpoint batch.

This is the high-throughput counterpart to \`document_endpoint\`. Supply one to ${DOCUMENT_ENDPOINT_BATCH_SIZE} endpoints from the same discovery pass. Each endpoint is independently validated, deduplicated, enriched, and persisted; failures do not discard successful siblings.

Do not build a manifest of the whole application. Submit a batch as soon as it reaches ${DOCUMENT_ENDPOINT_BATCH_SIZE} entries, then continue discovery.`,
    inputSchema: documentEndpointsInputSchema,
    execute: async (input: DocumentEndpointsInput, options) => {
      const executeEndpoint = endpointTool.execute;
      if (!executeEndpoint) {
        throw new Error("document_endpoint has no executor");
      }

      const results = await ctx.subagentSpawner.spawnMany(
        input.endpoints,
        async (endpoint): Promise<Record<string, unknown>> => {
          const result = await executeEndpoint(
            {
              ...endpoint,
              toolCallDescription: `Document ${endpoint.routePath}`,
            } satisfies DocumentEndpointInput,
            options,
          );
          if (
            typeof result !== "object" ||
            result === null ||
            Symbol.asyncIterator in result
          ) {
            throw new Error("document_endpoint returned a streaming result");
          }
          return result as Record<string, unknown>;
        },
        {
          concurrency: DOCUMENT_ENDPOINT_BATCH_SIZE,
          abortSignal: ctx.abortSignal,
        },
      );

      const endpoints = results.map(
        (result, index) =>
          result ?? {
            success: false,
            appName: input.endpoints[index]?.appName,
            routePath: input.endpoints[index]?.routePath,
            error: "endpoint_documentation_failed",
            message: "Endpoint documentation failed before returning a result.",
          },
      );
      const succeeded = endpoints.filter(
        (result) =>
          typeof result === "object" &&
          result !== null &&
          "success" in result &&
          result.success === true,
      ).length;

      return {
        success: succeeded > 0,
        endpoints,
        succeeded,
        failed: endpoints.length - succeeded,
        message: `Documented ${succeeded} of ${endpoints.length} endpoints.`,
      };
    },
  });
}
