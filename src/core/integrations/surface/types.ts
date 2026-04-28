import type {
  EndpointInfo,
  FrameworkId,
  HttpMethod,
} from "@pensar/surface";

/**
 * Apex-internal endpoint shape used by the surface-driven workflow.
 *
 * Surface emits one `EndpointInfo` per `(method, path)` pair — `GET /users`
 * and `POST /users` declared on the same handler are two rows. Apex's
 * downstream model treats one record per `(file, path)` with a
 * `method: string[]` field, so the integration helper consolidates surface
 * rows that share a route before they reach the enrichment agent.
 *
 * `ConsolidatedEndpoint` mirrors `EndpointInfo` exactly with two changes:
 *   - `method` is a deduplicated `string[]` instead of a single `HttpMethod`.
 *   - `handler` is a comma-joined string of distinct handler names across
 *     the consolidated rows (typically just one).
 *
 * See design doc section 1.3 ("Endpoint mapping") for the full rationale.
 */
export interface ConsolidatedEndpoint {
  method: string[];
  path: string;
  handler: string;
  file: string;
  line: number;
  framework: FrameworkId;
  auth: string[];
  internal: boolean;
}

/**
 * Re-exports for downstream consumers so they can refer to surface types
 * through a single import path.
 */
export type { EndpointInfo, FrameworkId, HttpMethod };
