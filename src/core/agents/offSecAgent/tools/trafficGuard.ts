import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { resolveExecutionPolicy } from "./executionPolicy";
import type { ToolContext } from "./types";

const MAX_INSPECTED_SOURCE_BYTES = 1_000_000;

export type TrafficClassification = {
  category:
    | "ordinary"
    | "bounded-rate-test"
    | "availability-impact"
    | "excessive-rate";
  reason?: string;
  requestedRate?: number;
  requestedConcurrency?: number;
};

const AVAILABILITY_IMPACT =
  /\b(?:slowloris|slowhttptest|ddos|volumetric\s+flood|fork\s*bomb|zip\s*bomb|decompression\s+bomb|billion\s+laughs|amplification\s+attack|memory\s+exhaustion|cpu\s+exhaustion)\b/i;
const RATE_TEST_TOOL =
  /(?:^|[;&|]\s*|\s)(?:ab|autocannon|ghz|hey|wrk|vegeta|siege|bombardier|h2load)\s/i;
const CONCURRENT_REQUEST_CODE =
  /Promise\.(?:all|allSettled)\s*\([\s\S]{0,300}(?:fetch|axios|request)|(?:fetch|axios|request)[\s\S]{0,300}Promise\.(?:all|allSettled)|(?:ThreadPoolExecutor|asyncio\.gather|xargs\s+-P)\b/i;

function largestNumber(input: string, patterns: RegExp[]): number | undefined {
  let largest: number | undefined;
  for (const pattern of patterns) {
    for (const match of input.matchAll(pattern)) {
      const value = Number(match[1]);
      if (Number.isFinite(value)) largest = Math.max(largest ?? value, value);
    }
  }
  return largest;
}

export function classifyTrafficAction(
  input: string,
  limits?: { requestsPerSecond: number; maxConcurrency: number },
): TrafficClassification {
  if (AVAILABILITY_IMPACT.test(input)) {
    return {
      category: "availability-impact",
      reason:
        "availability-impact technique is outside the bounded rate-test authorization",
    };
  }

  const requestedRate = largestNumber(input, [
    /(?:--rate|-rate|-qps|-r)\s*[=:]?\s*(\d+)/gi,
    /(?:requestsPerSecond|requests_per_second|rps)\s*[=:]\s*(\d+)/gi,
  ]);
  const requestedConcurrency = largestNumber(input, [
    /(?:--threads?|--concurrency|-c|-t|-P)\s*[=:]?\s*(\d+)/gi,
    /(?:concurrency|maxConcurrency|max_workers)\s*[=:]\s*(\d+)/gi,
  ]);
  const usesRateTestTool = RATE_TEST_TOOL.test(input);
  const usesConcurrentRequestCode = CONCURRENT_REQUEST_CODE.test(input);

  if (
    limits &&
    ((requestedRate !== undefined &&
      requestedRate > limits.requestsPerSecond) ||
      (requestedConcurrency !== undefined &&
        requestedConcurrency > limits.maxConcurrency))
  ) {
    return {
      category: "excessive-rate",
      reason: `requested traffic exceeds the engagement ceiling (${limits.requestsPerSecond} rps, concurrency ${limits.maxConcurrency})`,
      requestedRate,
      requestedConcurrency,
    };
  }

  if (usesConcurrentRequestCode && requestedConcurrency === undefined) {
    return {
      category: "excessive-rate",
      reason:
        "concurrent request programs must declare a bounded concurrency within the engagement ceiling",
      requestedRate,
    };
  }

  if (
    usesRateTestTool ||
    /\b(?:rate[ -]?limit|anti-?automation|request\s+burst|flood(?:ing)?)\b/i.test(
      input,
    )
  ) {
    return {
      category: "bounded-rate-test",
      requestedRate,
      requestedConcurrency,
    };
  }

  return { category: "ordinary" };
}

export class TrafficPolicyError extends Error {
  constructor(public readonly classification: TrafficClassification) {
    super(
      `Traffic policy blocked execution: ${classification.reason ?? classification.category}`,
    );
    this.name = "TrafficPolicyError";
  }
}

export function assertTrafficActionAllowed(
  input: string,
  ctx: ToolContext,
): void {
  const policy = ctx.executionPolicy ?? resolveExecutionPolicy(ctx.session);
  const classification = classifyTrafficAction(input, policy.traffic);
  if (
    classification.category === "availability-impact" ||
    classification.category === "excessive-rate" ||
    (classification.category === "bounded-rate-test" &&
      !policy.traffic.rateLimitTestingAllowed)
  ) {
    throw new TrafficPolicyError(classification);
  }
}

/** Read directly referenced local programs so policy is applied before launch. */
export function inspectReferencedPrograms(
  command: string,
  cwd: string,
): string {
  const sources: string[] = [];
  const referencedPaths = new Set<string>();
  const patterns = [
    /(?:^|[;&|]\s*)(?:bun(?:\s+run)?|node|python(?:3)?|bash|sh)\s+(?:(?:--?[\w-]+(?:=\S+)?|-\w)\s+)*(["']?[^\s;&|"']+\.(?:[cm]?[jt]s|py|sh)["']?)/gi,
    /(?:^|[;&|]\s*)uv\s+run\b[^;&|\n]*?(["']?[^\s;&|"']+\.py["']?)(?=\s|$)/gi,
    /(?:^|[;&|]\s*)(["']?(?:\.\/|\/)[^\s;&|"']+\.sh["']?)(?=\s|$)/gi,
  ];
  for (const pattern of patterns) {
    for (const match of command.matchAll(pattern)) {
      const rawPath = match[1]?.replace(/^["']|["']$/g, "");
      if (rawPath) referencedPaths.add(rawPath);
    }
  }
  for (const rawPath of referencedPaths) {
    if (!rawPath) continue;
    const path = isAbsolute(rawPath) ? rawPath : resolve(cwd, rawPath);
    if (!existsSync(path)) continue;
    try {
      const stat = statSync(path);
      if (!stat.isFile() || stat.size > MAX_INSPECTED_SOURCE_BYTES) continue;
      sources.push(
        `\n/* inspected program: ${path} */\n${readFileSync(path, "utf8")}`,
      );
    } catch {
      // The normal command execution path will surface unreadable programs.
    }
  }
  return `${command}${sources.join("")}`;
}
