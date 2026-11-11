import {
  normalizeCallbackDomains,
  type TargetScope,
} from "../../http/targetScope";
import type { CallbackBackend, ToolBackends } from "./types";

/** Anything that can carry a callbacks backend: a tool context or an agent input. */
export interface CallbackHost {
  readonly backends?: ToolBackends;
  /** A host on local backends passes the reader here; `LocalBackends` exposes it. */
  readonly callbacks?: CallbackBackend;
  readonly session: TargetScope;
  readonly target?: string;
}

/**
 * The callbacks backend, read the way the inbox is: from injected backends
 * when the host injects them, else from the hook `LocalBackends` copies.
 */
export function callbackBackend(
  host: CallbackHost,
): CallbackBackend | undefined {
  return host.backends ? host.backends.callbacks : host.callbacks;
}

/**
 * The run's callback domains, validated against this caller's own scope:
 * workers sharing one backend can have different targets, so the overlap
 * check runs per call. Empty means the feature is off; non-empty means there
 * is a receiver and a reader.
 */
export function callbackDomains(host: CallbackHost): string[] {
  const backend = callbackBackend(host);
  if (!backend) return [];
  return normalizeCallbackDomains(backend.domains, {
    ...host.session,
    targets: [
      ...(host.session.targets ?? []),
      ...(host.target ? [host.target] : []),
    ],
  });
}
