import type { SessionInfo } from "../../../session";

export type OffensiveExecutionPolicy = Readonly<{
  scope: Readonly<{
    allowedHosts: readonly string[];
    allowedPorts?: readonly number[];
    strict: boolean;
  }>;
  destructive: Readonly<{ allowed: boolean }>;
  traffic: Readonly<{
    rateLimitTestingAllowed: boolean;
    availabilityImpactAllowed: false;
    requestsPerSecond: number;
    burst: number;
    maxConcurrency: number;
  }>;
}>;

export function resolveExecutionPolicy(
  session: SessionInfo,
): OffensiveExecutionPolicy {
  const requestsPerSecond = Math.min(
    1000,
    Math.max(1, Math.round(session.config?.requestsPerSecond ?? 50)),
  );
  const rateLimitTestingAllowed =
    session.config?.allowRateLimitTesting === true;

  return Object.freeze({
    scope: Object.freeze({
      allowedHosts: Object.freeze([
        ...(session.config?.scopeConstraints?.allowedHosts ?? []),
      ]),
      ...(session.config?.scopeConstraints?.allowedPorts
        ? {
            allowedPorts: Object.freeze([
              ...session.config.scopeConstraints.allowedPorts,
            ]),
          }
        : {}),
      strict: session.config?.scopeConstraints?.strictScope === true,
    }),
    destructive: Object.freeze({
      allowed: session.config?.allowDestructiveActions === true,
    }),
    traffic: Object.freeze({
      rateLimitTestingAllowed,
      availabilityImpactAllowed: false as const,
      requestsPerSecond,
      burst: rateLimitTestingAllowed ? requestsPerSecond : 1,
      maxConcurrency: rateLimitTestingAllowed
        ? Math.min(requestsPerSecond, 32)
        : Math.min(requestsPerSecond, 4),
    }),
  });
}

export function buildExecutionPolicyPrompt(
  policy: OffensiveExecutionPolicy,
): string {
  const rate = policy.traffic.rateLimitTestingAllowed
    ? `Bounded rate-limit testing is authorized up to ${policy.traffic.requestsPerSecond} target requests/second, burst ${policy.traffic.burst}, concurrency ${policy.traffic.maxConcurrency}.`
    : `Rate-limit and light-DoS testing are out of scope. Target traffic is limited to ${policy.traffic.requestsPerSecond} requests/second with no burst and concurrency ${policy.traffic.maxConcurrency}.`;
  const destructive = policy.destructive.allowed
    ? "Destructive testing is authorized, but approval and least-invasive-proof requirements still apply."
    : "Destructive operations are blocked before execution.";

  return `\n\n## Enforced execution policy\n${rate}\n${destructive}\nCrash, resource-exhaustion, amplification, slow-connection, oversized-payload, and bomb-style availability tests are always blocked. Generated Bun/Python programs and subprocesses are governed by the same policy as built-in tools.`;
}
