import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { resolveArtifactFs } from "../../../tools/backends/resolve";
import {
  EndpointTransportEnum,
  GrpcEndpointMetadataSchema,
} from "../../specialized/attackSurface/grpcSchema";
import type { ToolContext } from "./types";

const inputSchema = z.object({
  appName: z
    .string()
    .min(1)
    .describe(
      "Application or service label; no prior documentation call is required.",
    ),
  routePath: z
    .string()
    .min(1)
    .refine(
      (value) => !/^https?:\/\//i.test(value),
      "Use a route or resource identity, not a full HTTP URL.",
    ),
  endpointType: z.enum(["api-endpoint", "web-endpoint", "asset"]),
  description: z
    .string()
    .min(1)
    .describe(
      "Observed behavior; distinguish observations from unverified possibilities.",
    ),
  evidence: z
    .array(z.string().min(1))
    .min(1)
    .describe(
      "References to requests, responses, source locations, or saved artifacts supporting this observation.",
    ),
  method: z.union([z.string(), z.array(z.string())]).optional(),
  transport: EndpointTransportEnum.optional(),
  grpc: GrpcEndpointMetadataSchema.optional(),
  file: z.string().optional(),
  line: z.number().int().positive().optional(),
  handler: z.string().optional(),
  authRequired: z.boolean().optional(),
  authentication: z.string().optional(),
  notes: z.string().optional(),
  toolCallDescription: z.string(),
});

export function documentEndpointV2(ctx: ToolContext) {
  if (ctx.attackSurfaceArtifactsPath && !ctx.backends)
    throw new Error("Recon artifacts require explicit backends");
  return tool({
    description:
      "Save an endpoint observation and its evidence references as a session artifact. This records only the supplied facts: it does not infer threats, score risk, call another model, launch research, or modify connected Pensar workspace records. Use create_workspace_endpoint for a requested workspace mutation.",
    inputSchema,
    execute: async (input) => {
      const { toolCallDescription: _, ...observation } =
        inputSchema.parse(input);
      const appId = createHash("sha256")
        .update(observation.appName)
        .digest("hex")
        .slice(0, 16);
      const filepath = join(
        ctx.attackSurfaceArtifactsPath ??
          join(ctx.session.rootPath, "observations", "endpoints"),
        appId,
        `endpoint_${randomUUID()}.json`,
      );
      const record = {
        ...observation,
        schemaVersion: 2,
        discoveredAt: new Date().toISOString(),
        sessionId: ctx.session.id,
        target: ctx.session.targets[0],
      };
      const result = await resolveArtifactFs(ctx).write(
        filepath,
        JSON.stringify(record, null, 2),
        { mode: "overwrite" },
      );
      if (!result.success)
        throw new Error(`Endpoint artifact write failed: ${result.error}`);
      return {
        success: true,
        filepath,
        appName: observation.appName,
        routePath: observation.routePath,
      };
    },
  });
}
