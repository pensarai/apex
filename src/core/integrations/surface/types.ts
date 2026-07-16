import type {
  EndpointKind,
  EndpointTransport,
  FrameworkId,
  GrpcMeta,
} from "@pensar/surface";

/**
 * Apex's per-route view of surface output. Surface emits one row per
 * `(method, path)`; apex consolidates rows sharing `(file, path)` so
 * `method` is a deduplicated array and `handler` joins distinct names.
 */
export interface ConsolidatedEndpoint {
  method: string[];
  path: string;
  handler: string;
  file: string;
  line: number;
  framework: FrameworkId;
  kind: EndpointKind;
  auth: string[];
  internal: boolean;
  /** Wire transport (absent/"http" for plain HTTP; "grpc"/"grpc_web"/"connect" for gRPC). */
  transport?: EndpointTransport;
  /** gRPC service/method/streaming metadata, present when transport is a gRPC variant. */
  grpc?: GrpcMeta;
}

export type { EndpointTransport, FrameworkId, GrpcMeta };
