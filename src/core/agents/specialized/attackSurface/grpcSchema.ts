import { z } from "zod";

// Zod-only leaf module: keeps this shareable between the live tool and
// `schemas.ts` without a circular import through `whiteboxAttackSurface`.

export const EndpointTransportEnum = z.enum([
  "http",
  "grpc",
  "grpc_web",
  "connect",
]);

export const GrpcStreamingTypeEnum = z.enum([
  "unary",
  "server_stream",
  "client_stream",
  "bidi",
]);

const GrpcSchemaSourceEnum = z.enum([
  "proto",
  "reflection",
  "protoset",
  "js_bundle",
  "gateway_derived",
  "unknown",
]);

const GrpcGatewayTypeEnum = z.enum(["rest", "graphql", "connect"]);

export const GrpcEndpointMetadataSchema = z.object({
  serviceFqn: z
    .string()
    .describe("Fully-qualified service name, e.g. 'account.v1.AccountService'"),
  method: z.string().describe("RPC method name, e.g. 'GetAccount'"),
  streamingType: GrpcStreamingTypeEnum.default("unary"),
  reflectionAvailable: z.boolean().optional(),
  schemaSource: GrpcSchemaSourceEnum.optional(),
  host: z
    .string()
    .nullish()
    .describe("Authority override; null falls back to the app domain"),
  frontingGatewayOperation: z
    .object({
      gatewayType: GrpcGatewayTypeEnum,
      operation: z.string(),
    })
    .nullish(),
});

export type EndpointTransport = z.infer<typeof EndpointTransportEnum>;
export type GrpcEndpointMetadata = z.infer<typeof GrpcEndpointMetadataSchema>;

// ---------------------------------------------------------------------------
// gRPC pentest context — the slice of gRPC metadata a pentest agent needs to
// run the gRPC test battery instead of treating the method as an HTTP path.
// Lives here (leaf module) so it can be shared by the pentest agent, the
// swarm target shape, tool contexts, and orchestration tools without cycles.
// ---------------------------------------------------------------------------

export const GrpcPentestContextSchema = z.object({
  transport: z.enum(["grpc", "grpc_web", "connect"]),
  serviceFqn: z.string(),
  method: z.string(),
  streamingType: GrpcStreamingTypeEnum.optional(),
  reflectionAvailable: z.boolean().optional(),
  schemaSource: GrpcSchemaSourceEnum.optional(),
  host: z
    .string()
    .nullish()
    .describe("Authority override; null falls back to the app domain"),
  frontingGatewayOperation: z
    .object({
      gatewayType: GrpcGatewayTypeEnum,
      operation: z.string(),
    })
    .nullish(),
});

export type GrpcPentestContext = z.infer<typeof GrpcPentestContextSchema>;

/**
 * Derive minimal gRPC metadata (`serviceFqn` / `method`) from a wire path of
 * the form `/package.Service/Method`. Used when an endpoint is marked with a
 * gRPC transport but carries no `grpc` object, so it still runs the gRPC
 * battery instead of silently degrading to HTTP.
 */
function deriveGrpcMetadataFromPath(
  path: string | undefined,
):
  | (Partial<GrpcEndpointMetadata> &
      Pick<GrpcEndpointMetadata, "serviceFqn" | "method">)
  | undefined {
  if (!path) return undefined;
  const wire = path.replace(/^\//, "").split("?")[0];
  const slash = wire.lastIndexOf("/");
  if (slash <= 0 || slash === wire.length - 1) return undefined;
  return { serviceFqn: wire.slice(0, slash), method: wire.slice(slash + 1) };
}

/**
 * Build a {@link GrpcPentestContext} from an endpoint's `transport` + `grpc`
 * metadata (as produced by whitebox discovery / `document_endpoint`). Returns
 * `undefined` for plain HTTP endpoints, so callers can attach the result to a
 * target unconditionally. When `transport` is a gRPC variant but the `grpc`
 * object is missing, `serviceFqn` / `method` are derived from the wire `path`
 * so the target is still tested as gRPC.
 */
export function toGrpcPentestContext(
  transport: EndpointTransport | undefined,
  grpc: GrpcEndpointMetadata | undefined,
  path?: string,
): GrpcPentestContext | undefined {
  if (!transport || transport === "http") return undefined;
  const derived = grpc ?? deriveGrpcMetadataFromPath(path);
  if (!derived) return undefined;
  return {
    transport,
    serviceFqn: derived.serviceFqn,
    method: derived.method,
    streamingType: derived.streamingType,
    reflectionAvailable: derived.reflectionAvailable,
    schemaSource: derived.schemaSource,
    host: derived.host,
    frontingGatewayOperation: derived.frontingGatewayOperation,
  };
}

/**
 * When a gRPC method's authority (`grpc.host`) differs from the app domain,
 * build the `grpc://<authority>/<wire-path>` target so the method's real
 * authority reaches the pentest agent. Returns `undefined` when there is no
 * host override, so callers fall back to their default target construction.
 */
export function grpcAuthorityTarget(
  grpc: GrpcPentestContext | undefined,
  path: string,
): string | undefined {
  if (!grpc?.host) return undefined;
  const wirePath = path.startsWith("/") ? path : `/${path}`;
  return `grpc://${grpc.host}${wirePath}`;
}
