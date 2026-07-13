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

export const GrpcSchemaSourceEnum = z.enum([
  "proto",
  "reflection",
  "protoset",
  "js_bundle",
  "gateway_derived",
  "unknown",
]);

export const GrpcGatewayTypeEnum = z.enum(["rest", "graphql", "connect"]);

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
export type GrpcStreamingType = z.infer<typeof GrpcStreamingTypeEnum>;
export type GrpcSchemaSource = z.infer<typeof GrpcSchemaSourceEnum>;
export type GrpcGatewayType = z.infer<typeof GrpcGatewayTypeEnum>;
export type GrpcEndpointMetadata = z.infer<typeof GrpcEndpointMetadataSchema>;
