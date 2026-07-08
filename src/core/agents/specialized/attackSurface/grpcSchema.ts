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
