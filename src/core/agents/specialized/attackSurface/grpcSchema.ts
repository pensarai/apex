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
  frontingGatewayOperation: z
    .object({
      gatewayType: GrpcGatewayTypeEnum,
      operation: z.string(),
    })
    .nullish(),
});

export type GrpcPentestContext = z.infer<typeof GrpcPentestContextSchema>;

/**
 * Build a {@link GrpcPentestContext} from an endpoint's `transport` + `grpc`
 * metadata (as produced by whitebox discovery / `document_endpoint`). Returns
 * `undefined` for plain HTTP endpoints or when gRPC metadata is missing, so
 * callers can attach the result to a target unconditionally.
 */
export function toGrpcPentestContext(
  transport: EndpointTransport | undefined,
  grpc: GrpcEndpointMetadata | undefined,
): GrpcPentestContext | undefined {
  if (!transport || transport === "http" || !grpc) return undefined;
  return {
    transport,
    serviceFqn: grpc.serviceFqn,
    method: grpc.method,
    streamingType: grpc.streamingType,
    reflectionAvailable: grpc.reflectionAvailable,
    schemaSource: grpc.schemaSource,
    frontingGatewayOperation: grpc.frontingGatewayOperation,
  };
}
