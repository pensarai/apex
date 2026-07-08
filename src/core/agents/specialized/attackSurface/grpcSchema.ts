import { z } from "zod";

/**
 * Transport + gRPC schemas for endpoints. Kept in a zod-only leaf module (no
 * imports from the attack-surface agents) so both the live `document_endpoint`
 * tool and the exported `schemas.ts` contract can share them without creating a
 * circular import through `whiteboxAttackSurface`.
 */

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

export const GrpcEndpointMetadataSchema = z.object({
  serviceFqn: z
    .string()
    .describe("Fully-qualified service name, e.g. 'account.v1.AccountService'"),
  method: z.string().describe("RPC method name, e.g. 'GetAccount'"),
  fullMethodPath: z
    .string()
    .describe(
      "Verbatim wire path '/package.Service/Method', e.g. '/account.v1.AccountService/GetAccount'",
    ),
  streamingType: GrpcStreamingTypeEnum.default("unary"),
  reflectionAvailable: z.boolean().optional(),
  schemaSource: z
    .enum([
      "proto",
      "reflection",
      "protoset",
      "js_bundle",
      "gateway_derived",
      "unknown",
    ])
    .optional(),
  host: z
    .string()
    .nullish()
    .describe("Authority override; null falls back to the app domain"),
  frontingGatewayOperation: z
    .object({
      gatewayType: z.enum(["rest", "graphql", "connect"]),
      operation: z.string(),
    })
    .nullish(),
});

export type EndpointTransport = z.infer<typeof EndpointTransportEnum>;
export type GrpcEndpointMetadata = z.infer<typeof GrpcEndpointMetadataSchema>;
