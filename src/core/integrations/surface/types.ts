import type {
  EndpointInfo,
  FrameworkId,
  EndpointKind,
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
}

export type { EndpointInfo, FrameworkId };
