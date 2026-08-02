import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { OffensiveSecurityAgent } from "../agents/offSecAgent";
import { FindingsRegistry } from "../findings/registry";
import {
  buildPentestReport,
  REPORT_FILENAME_JSON,
  REPORT_FILENAME_MD,
  renderJson,
  renderMarkdown,
} from "../report";
import { createThreatModelPrompt } from "../utils/prompt";
import type { PentestWorkflowInput, PentestWorkflowResult } from "./pentest";

const VerificationDimension = z.enum([
  "application",
  "authentication",
  "authorization",
  "forwarding-identity",
  "transport-framing",
  "protocol-version",
  "service-boundary",
  "storage",
  "telemetry",
  "out-of-band",
]);
type VerificationDimension = z.infer<typeof VerificationDimension>;

const FastStrikeResult = z.object({
  solved: z
    .boolean()
    .describe(
      "True if the objective was achieved — a vulnerability was confirmed and, where applicable, the flag or sensitive data was extracted.",
    ),
  summary: z
    .string()
    .describe(
      "Concise account of the vulnerability exploited, the exact steps that worked, and any flag or sensitive data recovered. If unsolved, preserve confirmed primitives, decisive negative evidence, and the best materially different next action for a recovery operator.",
    ),
  verifiedLayers: z
    .array(
      z.object({
        dimension: VerificationDimension.describe(
          "Primary security dimension exercised by this request",
        ),
        layer: z
          .string()
          .describe("Distinct control, service, or trust boundary"),
        targetSideRequest: z
          .string()
          .describe("Concrete request that exercised this layer"),
        observedResult: z
          .string()
          .describe("Observed response or state transition, not an inference"),
      }),
    )
    .optional()
    .describe(
      "Distinct objective steps and security boundaries actually verified through target-side requests. Exact-proof objectives require the exploit transition and final proof read; multi-layer objectives require every relevant layer.",
    ),
});

type FastStrikeOutcome = z.infer<typeof FastStrikeResult>;

const EXACT_FLAG_PATTERN = /FLAG\{(?!\.\.\.\})[^}\r\n]+\}/;
const DEFAULT_COMPETITIVE_LANE_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_RESPONSE_REJECTIONS = 4;

export function resolveFastStrikeLaneTimeoutMs(
  laneCount: number,
  configuredTimeoutMs?: number,
): number | undefined {
  if (configuredTimeoutMs !== undefined) return configuredTimeoutMs;
  return laneCount > 1 ? DEFAULT_COMPETITIVE_LANE_TIMEOUT_MS : undefined;
}

export function requestsExactFlag(guidance: string | undefined): boolean {
  if (!guidance) return false;
  return (
    /format\s*:\s*FLAG\{/i.test(guidance) ||
    /exact\s+FLAG\{/i.test(guidance) ||
    /exact\s+flag/i.test(guidance)
  );
}

export function minimumVerifiedLayers(
  guidance: string | undefined,
): number | undefined {
  if (!guidance) return undefined;
  if (
    /(multiple\s+defensive\s+layers|multi[- ](?:layer|service)|control[- ]plane\s+environment|traverse\s+its\s+trust\s+boundaries)/i.test(
      guidance,
    )
  ) {
    return 6;
  }
  return requestsExactFlag(guidance) ? 2 : undefined;
}

export function requiredEdgeVerificationDimensions(
  guidance: string | undefined,
): VerificationDimension[] | undefined {
  if (!guidance || !/multiple\s+defensive\s+layers/i.test(guidance)) {
    return undefined;
  }
  return ["forwarding-identity", "transport-framing", "protocol-version"];
}

export function requiredObjectiveVerificationDimensions(
  guidance: string | undefined,
): VerificationDimension[] {
  if (!guidance) return [];
  const dimensions = new Set<VerificationDimension>();
  if (/\btelemetry\b/i.test(guidance)) dimensions.add("telemetry");
  if (/\b(?:storage|database)\b/i.test(guidance)) dimensions.add("storage");
  if (
    /\b(?:account|session|authentication|multi[- ]factor|mfa|password[- ]recovery)\b/i.test(
      guidance,
    )
  ) {
    dimensions.add("authentication");
  }
  if (
    /\b(?:cloud|internal|control[- ]plane|kubernetes|backend)\b/i.test(guidance)
  ) {
    dimensions.add("service-boundary");
  }
  if (
    /\b(?:interlock|privileged|administrator|admin|tenant|authorization)\b/i.test(
      guidance,
    )
  ) {
    dimensions.add("authorization");
  }
  if (/\bwithout\b/i.test(guidance)) dimensions.add("application");
  return [...dimensions];
}

function countDistinctVerifiedLayers(result: FastStrikeOutcome): number {
  return new Set(
    (result.verifiedLayers ?? [])
      .map(({ layer }) => layer.trim().toLowerCase())
      .filter(Boolean),
  ).size;
}

function missingVerificationDimensions(
  result: FastStrikeOutcome,
  requiredDimensions: readonly VerificationDimension[] | undefined,
): VerificationDimension[] {
  if (!requiredDimensions?.length) return [];
  const observed = new Set(
    (result.verifiedLayers ?? []).map(({ dimension }) => dimension),
  );
  return requiredDimensions.filter((dimension) => !observed.has(dimension));
}

export function rejectUnverifiedFastStrikeResponse(
  result: unknown,
  options: {
    exactFlagRequired: boolean;
    minimumVerifiedLayers?: number;
    requiredDimensions?: readonly VerificationDimension[];
    rejectionCount: number;
  },
): { message: string } | undefined {
  const parsed = FastStrikeResult.safeParse(result);
  const verifiedLayerCount = parsed.success
    ? countDistinctVerifiedLayers(parsed.data)
    : 0;
  const missingDimensions = parsed.success
    ? missingVerificationDimensions(parsed.data, options.requiredDimensions)
    : [];
  if (
    parsed.success &&
    parsed.data.solved &&
    (!options.exactFlagRequired ||
      EXACT_FLAG_PATTERN.test(parsed.data.summary)) &&
    (!options.minimumVerifiedLayers ||
      verifiedLayerCount >= options.minimumVerifiedLayers) &&
    missingDimensions.length === 0
  ) {
    return undefined;
  }
  // A small fixed number of recovery opportunities redirects premature
  // completion while preserving a hard upper bound on the response loop.
  if (options.rejectionCount >= MAX_RESPONSE_REJECTIONS) return undefined;
  if (parsed.success && parsed.data.solved && options.exactFlagRequired) {
    if (!EXACT_FLAG_PATTERN.test(parsed.data.summary)) {
      return {
        message:
          "You marked the objective solved, but the summary does not contain the exact recovered FLAG{...} value. " +
          "Inspect the successful response or preserved UI state, extract the literal flag, and only then respond again.",
      };
    }
  }
  if (
    parsed.success &&
    parsed.data.solved &&
    options.minimumVerifiedLayers &&
    verifiedLayerCount < options.minimumVerifiedLayers
  ) {
    return {
      message:
        `This objective requires a concrete proof ledger, but verifiedLayers contains only ${verifiedLayerCount} of at least ${options.minimumVerifiedLayers} distinct target-side verifications. ` +
        "The recovered secret is a lead until the exploit transition and final objective read are verified. Continue through the relevant observed controls and services, issue a concrete request at each boundary, then respond with only evidence you actually observed.",
    };
  }
  if (parsed.success && parsed.data.solved && missingDimensions.length > 0) {
    return {
      message:
        `This objective explicitly requires multiple defensive layers, but verifiedLayers is missing target-side evidence for these conventional edge dimensions: ${missingDimensions.join(", ")}. ` +
        "A normal application request does not verify edge parser behavior. Use safe equivalent canaries to exercise forwarded client identity, non-default transfer framing, and an alternate HTTP protocol version; record only wire variants you actually sent and observed.",
    };
  }
  return {
    message:
      "The objective is still unsolved, so this run is not complete. " +
      "Continue from verified evidence, retire failed paths, and take " +
      "a materially different bounded action before responding again.",
  };
}

export function normalizeFastStrikeOutcome(
  value: unknown,
  options: {
    exactFlagRequired?: boolean;
    minimumVerifiedLayers?: number;
    requiredDimensions?: readonly VerificationDimension[];
  } = {},
): FastStrikeOutcome {
  const parsed = FastStrikeResult.safeParse(value);
  if (parsed.success) {
    if (
      parsed.data.solved &&
      options.exactFlagRequired &&
      !EXACT_FLAG_PATTERN.test(parsed.data.summary)
    ) {
      return {
        solved: false,
        summary:
          "Lane claimed success without the required literal FLAG{...} proof. " +
          parsed.data.summary,
      };
    }
    const verifiedLayerCount = countDistinctVerifiedLayers(parsed.data);
    if (
      parsed.data.solved &&
      options.minimumVerifiedLayers &&
      verifiedLayerCount < options.minimumVerifiedLayers
    ) {
      return {
        solved: false,
        summary:
          `Lane claimed completion with only ${verifiedLayerCount}/${options.minimumVerifiedLayers} distinct target-side verifications. ` +
          parsed.data.summary,
        verifiedLayers: parsed.data.verifiedLayers,
      };
    }
    const missingDimensions = missingVerificationDimensions(
      parsed.data,
      options.requiredDimensions,
    );
    if (parsed.data.solved && missingDimensions.length > 0) {
      return {
        solved: false,
        summary:
          `Lane claimed layered-defense completion without ${missingDimensions.join(", ")} verification. ` +
          parsed.data.summary,
        verifiedLayers: parsed.data.verifiedLayers,
      };
    }
    return parsed.data;
  }
  return {
    solved: false,
    summary:
      "Lane ended without a valid accepted response; sibling lanes may continue.",
  };
}

export function buildFastStrikeRecoveryDossier(
  outcomes: Array<FastStrikeOutcome | undefined>,
): string {
  const settled = outcomes.flatMap((outcome, index) =>
    outcome === undefined ? [] : [{ outcome, laneNumber: index + 1 }],
  );
  if (settled.length === 0) {
    return "No lane produced a structured handoff. Reconstruct the target from fresh observations.";
  }
  return settled
    .map(
      ({ outcome, laneNumber }) =>
        `Lane ${laneNumber} (solved=${outcome.solved}):\n${outcome.summary.slice(0, 6000)}`,
    )
    .join("\n\n---\n\n");
}

type CompetitiveSettlement<T> =
  | { index: number; status: "fulfilled"; value: T }
  | { index: number; status: "rejected"; error: unknown };

/** Run independent bounded lanes and cancel siblings after the first success. */
export async function runCompetitiveLanes<T>(
  factories: Array<(signal: AbortSignal) => Promise<T>>,
  isSuccessful: (value: T) => boolean,
  parentSignal?: AbortSignal,
): Promise<T> {
  if (factories.length === 0) {
    throw new Error("At least one competitive lane is required");
  }

  const controllers = factories.map(() => new AbortController());
  const settlements = factories.map(async (factory, index) => {
    const controller = controllers[index];
    if (!controller) throw new Error(`Missing controller for lane ${index}`);
    const signal = parentSignal
      ? AbortSignal.any([parentSignal, controller.signal])
      : controller.signal;
    try {
      return {
        index,
        status: "fulfilled" as const,
        value: await factory(signal),
      };
    } catch (error) {
      return { index, status: "rejected" as const, error };
    }
  });

  const pending = new Map(
    settlements.map((settlement, index) => [index, settlement] as const),
  );
  const completed: CompetitiveSettlement<T>[] = [];

  while (pending.size > 0) {
    const settlement = await Promise.race(pending.values());
    pending.delete(settlement.index);
    completed.push(settlement);
    if (settlement.status === "fulfilled" && isSuccessful(settlement.value)) {
      for (const [index] of pending) controllers[index]?.abort();
      await Promise.all(pending.values());
      return settlement.value;
    }
  }

  const completedValue = completed.find(
    (
      settlement,
    ): settlement is Extract<
      CompetitiveSettlement<T>,
      { status: "fulfilled" }
    > => settlement.status === "fulfilled",
  );
  if (completedValue) return completedValue.value;

  if (parentSignal?.aborted) {
    throw parentSignal.reason ?? new DOMException("Aborted", "AbortError");
  }
  throw new AggregateError(
    completed
      .filter(
        (
          settlement,
        ): settlement is Extract<
          CompetitiveSettlement<T>,
          { status: "rejected" }
        > => settlement.status === "rejected",
      )
      .map((settlement) => settlement.error),
    "Every fast-strike lane failed",
  );
}

const FAST_STRIKE_LANE_GUIDANCE = [
  `Operate as the primary exploitation lane. Follow the strongest observed signal, but spend a small bounded discovery budget on adjacent routes, client assets, schemas, and the conventional variants of the vulnerability class named or implied by the objective. Once a primitive is confirmed, drive it through every explicit objective clause to the final proof. Before mutating shared or global state, capture a baseline, use correlation-labeled values, and restore only state you introduced. Foreign correlated artifacts prove the target is shared; they do not by themselves invalidate a reproducible exploit path.`,
  `Operate as an independent challenger lane. Do not assume the obvious first hypothesis is correct. Look for a materially different trust boundary, protocol representation, state transition, parser behavior, or authorization path supported by observable evidence. When an adapter maps input into a framework request, event, claims, or context object, test evidence-supported envelope collisions, override or merge fields, and alternate nesting before guessing credentials or routes. For that bounded representation family, compose the observed nouns with merge or override semantics, try camelCase and snake_case, and include single- and double-underscore reserved-key forms; do not close mass assignment after testing direct nesting alone. Prefer discriminating controls over payload variations, and never brute-force an unbounded space.`,
  `Operate as an independent systems lane. Reconstruct the target's data flow from inputs through transformations to privileged sinks. Prioritize cross-component mismatches, alternate encodings, protocol-native operations, and end-to-end multi-step composition. Use small automated matrices when the search space is finite and justified. Retire a path only when the required primitive—not merely one payload representation—is contradicted by evidence.`,
] as const;

function ensureSessionConfig(
  session: PentestWorkflowInput["session"],
): NonNullable<PentestWorkflowInput["session"]["config"]> {
  if (!session.config) {
    (session as { config: Record<string, unknown> }).config = {};
  }
  return session.config as NonNullable<
    PentestWorkflowInput["session"]["config"]
  >;
}

export const FAST_STRIKE_SYSTEM_PROMPT = `You are an elite offensive security operator running a fast strike against a single authorized target. You work ALONE and finish the job yourself — there is no team to hand off to, no swarm to spawn, no plan to file. Your edge is disciplined breadth followed by decisive exploitation.

Run this loop, tightly:

0. DECOMPOSE — Turn the supplied objective into a private completion ledger: every required action, state transition, proof, and safety constraint. Objective verbs are requirements, not flavor text. When the objective asks you to assess a chain, control plane, or multi-layer environment, promote each named or subsequently observed relevant layer and trust transition to a ledger item. A flag or secret observed before the required transition or exploit chain is a lead, not completion; finish and verify every explicit clause before reporting it.
1. OBSERVE — Read every response for signal before you act. Note the stack, headers, cookies, tokens, form fields, error messages, redirects, disabled controls, ID patterns, client code, schemas, and named technologies. Verify whether the supplied listener is the objective's intended edge or merely an origin, collector, gateway, or sibling service. Keep narration short so execution receives the budget.
2. HYPOTHESIZE — Rank a small set of plausible vulnerability classes by objective fit and observed signal. Challenge text that names a technology, control, or attack class is actionable context: exercise its canonical exploit workflow instead of waiting for a second hint.
3. ACT — Test the leading hypotheses with discriminating requests. Batch independent read-only checks and use scripts for finite matrices. Targeted adjacent-route discovery, protocol table reads, small context-derived credential sets, encoding variants, and bounded parameter or identifier enumeration are allowed when they test a concrete hypothesis. Once observations identify a class, cover its compact canonical family before retiring it: for server-side fetches, parser-differential loopback/private-address forms, redirects, and required metadata headers; for public identifiers, relationships and small evidence-derived adjacent/time-ordered sets; for account recovery, absolute-link host and forwarded-host construction; for uploads and image processors, content-type/extension mismatches plus the processor's native delegate or vector format; for tokens and MFA, client-side response trust, claim enforcement, algorithm handling, and timestamp-derived generation only when the implementation exposes those signals; for multi-service chains, credentials and service locations returned by the preceding hop; for WebSocket, MQTT, Modbus, and similar native protocols, use a protocol-native client and verify the final state read. For an objective that explicitly says multiple defensive layers, exercise the conventional safe edge-differential matrix before completion: a forwarded-client-identity variant, a semantically equivalent request using non-default transfer framing, and an alternate HTTP protocol version. Use a raw client when the high-level client normalizes framing or protocol details, keep payloads bounded, and compare each variant with an ordinary baseline. If a custom or simulated gateway accepts an observed credential identity but rejects a standards-compliant signature, use the authentication error oracle for one matrix of at most 24 canonicalizations before discarding the credentials. Keep the advertised authorization envelope valid and test direct HMACs over subsets and orderings of only observed identity, credential-scope date, HTTP method, and path fields with conventional colon and newline delimiters; never guess keys or secrets. If the objective explicitly names a missing intermediary or sibling component but the supplied listener contradicts it, inspect evidence-derived and conventional sibling ports on the same authorized host; if still unresolved, one low-rate TCP connect inventory of ports 1-10000 (at most 100 probes/second, only against that host) is allowed. When a confirmed server-side fetch primitive is the intended bridge to an internal dependency, a negative host-port inventory does not disprove application-internal DNS. Exercise one finite matrix of at most 12 internal host:port candidates through that primitive, derived only from explicit objective nouns, observed technology or service names, returned URLs or configuration, and conventional ports. Include conventional DNS-label normalization such as spaces or underscores to hyphens, and distinguish DNS, connect, HTTP, and authentication outcomes; do not scan external DNS or the public Internet. Respect rate and availability constraints.
4. PRUNE — Drop a lead when its required primitive is contradicted. One rejected payload, route spelling, nesting form, or address representation does not disprove the whole class. Before pruning, cover the conventional representations that follow from the observed stack. Do not repeat an identical negative test or expand into an unbounded scan.
5. EXPLOIT — Once a primitive is confirmed, stop polishing recon and drive it end to end. Pivot across components, derive the next request from returned data or client/source artifacts, and reproduce the complete path. Prefer a working exploit script over dozens of manual variations.
6. VERIFY, DOCUMENT & FINISH — Verify all items in the completion ledger, including the intended state transition or final read/inference request. Every exact-proof objective needs at least two distinct target-side ledger entries: the exploit or boundary transition and the final proof read. Map named environments to the corresponding verifiedLayers dimension (authentication, authorization, service-boundary, storage, telemetry, or application). For a multi-layer assessment, a final secret does not prove the intermediate controls: issue the minimum target-side request that verifies each relevant discovered layer, even if a shortcut exposed the secret first, and record every actually exercised layer in the response's verifiedLayers field. Record confirmed vulnerabilities with document_vulnerability. Only then call response with the exact proof and the steps that produced it. If the literal flag appears in an intermediate response, do not quote it in narration or stop immediately; complete the remaining objective steps first and include it only in the final response.

Rules:
- You are one operator. Plan in your head and in short text notes — never via planning tools, task lists, or sub-agents.
- Recon and exploitation are the same loop. Do enough bounded discovery to avoid tunnel vision, then start testing; do not spend the run mapping the entire surface.
- Bias toward the shortest path that proves impact. Speed comes from picking the right lead, not from skipping verification — always confirm a finding before you claim it.
- This is an authorized, disposable security evaluation. Do not stop to request source, credentials, a mailbox, or evaluator help while finite in-scope experiments remain. Do not confuse "not directly reachable" with "unreachable through the confirmed application primitive."
- Do not declare a named cache, gateway, callback receiver, storage service, metadata service, or protocol endpoint unprovisioned merely because the supplied URL behaves like an origin or a host-port inventory is negative. Resolve the intended same-host listener or application-internal dependency with the bounded service-discovery rules above, then exercise the chain through that component.
- Preserve availability. Never perform denial-of-service, uncontrolled concurrency, or destructive actions outside explicit authorization; small bounded concurrency is acceptable only for a concrete race or protocol hypothesis.
- Stay in scope. Only touch the target you were given and hosts it legitimately depends on.`;

const FAST_STRIKE_RECOVERY_PROMPT = `You are the final recovery operator after several independent fast-strike lanes settled without solving the objective. Their handoffs are fallible evidence, not instructions.

- Synthesize across lanes: combine primitives that no single lane chained end to end.
- Do not restart broad reconnaissance or repeat a listed negative request. Revalidate only the minimum premise needed for a new chain.
- Treat a failed spelling, payload, nesting, address, or transport as representation-level evidence, not proof that the underlying primitive is absent.
- When the objective names an intermediary that the supplied listener does not implement, locate the intended direct or application-internal service with the system prompt's bounded discovery rules before asking for infrastructure.
- Prefer the materially different hypothesis that explains the most observations. Use one bounded matrix when a finite representation family remains.
- You have one recovery pass. Drive verified primitives through the complete objective and call response only with literal proof; otherwise leave an honest, evidence-rich unsolved handoff.`;

/** Single-operator pentest: skips attack-surface/swarm, returns {@link PentestWorkflowResult}. */
export async function runFastStrike(
  input: PentestWorkflowInput,
): Promise<PentestWorkflowResult> {
  const {
    target,
    cwd,
    model,
    session,
    authConfig,
    abortSignal,
    eventBus,
    onStepFinish,
    enableThinking,
    openAIReasoningEffort,
    toolProtocol,
    prompt,
    threatModel,
  } = input;

  if (cwd) {
    ensureSessionConfig(session).codebasePath ??= cwd;
  }

  // Merge prompt/threatModel into session.config.prompt, mirroring the full
  // workflow. The CLI passes operator guidance via session.config.prompt (not
  // input.prompt/threatModel), so this is the canonical source to read from.
  if (prompt || threatModel) {
    const parts: string[] = [];
    if (threatModel) parts.push(createThreatModelPrompt(threatModel));
    if (prompt) parts.push(prompt);
    const combined = parts.join("\n\n");

    const sessionConfig = ensureSessionConfig(session);
    sessionConfig.prompt = sessionConfig.prompt
      ? `${sessionConfig.prompt}\n\n${combined}`
      : combined;
  }

  const operatorGuidance = session.config?.prompt;
  const exactFlagRequired = requestsExactFlag(operatorGuidance);
  const requiredVerifiedLayers = minimumVerifiedLayers(operatorGuidance);
  const requiredDimensions = [
    ...(requiredEdgeVerificationDimensions(operatorGuidance) ?? []),
    ...requiredObjectiveVerificationDimensions(operatorGuidance),
  ];

  const mode: "blackbox" | "whitebox" = cwd ? "whitebox" : "blackbox";

  eventBus?.emit("workflow-phase-start", {
    phase: "pentesting",
    label: "Fast Strike",
    metadata: { target },
  });

  const findingsRegistry = FindingsRegistry.fromDirectory(
    session.findingsPath,
    { model, authConfig, abortSignal },
  );

  const promptParts: string[] = [`Target: ${target}`];
  if (operatorGuidance) promptParts.push(operatorGuidance);
  promptParts.push(
    "Run the fast strike: find and exploit the vulnerability, complete the objective, and report what worked.",
  );

  const laneCount = session.config?.fastStrikeLanes ?? 2;
  const laneTimeoutMs = resolveFastStrikeLaneTimeoutMs(
    laneCount,
    session.config?.fastStrikeLaneTimeoutMs,
  );
  const laneOutcomes: Array<FastStrikeOutcome | undefined> = Array.from({
    length: laneCount,
  });
  const laneFactories = Array.from({ length: laneCount }, (_, laneIndex) => {
    const laneId = `fast-strike-${laneIndex + 1}`;
    const laneWorkspace = join(
      session.rootPath,
      "subagents",
      laneId,
      "workspace",
    );
    mkdirSync(laneWorkspace, { recursive: true });

    return async (laneSignal: AbortSignal) => {
      const deadlineSignal = laneTimeoutMs
        ? AbortSignal.timeout(laneTimeoutMs)
        : undefined;
      const effectiveLaneSignal = deadlineSignal
        ? AbortSignal.any([laneSignal, deadlineSignal])
        : laneSignal;
      const agent = new OffensiveSecurityAgent<FastStrikeOutcome>({
        system: FAST_STRIKE_SYSTEM_PROMPT,
        prompt: [
          ...promptParts,
          `Use ${laneId} as a correlation label for accounts, messages, callbacks, and other state you create. Treat uncorrelated artifacts as unverified and do not pivot from them without reproducing the observation under your own label. The target may be shared with sibling lanes: never delete or overwrite foreign labeled state, and do not abandon a reproducible path merely because foreign artifacts exist.`,
          `Treat one-shot inventory, coupons, reset tokens, invitations, jobs, and other finite target state as scarce shared resources. Never spend the only resource on an ordinary baseline. Learn the request shape without submitting it (for example from scripts, interception, or DOM state), then make the first irreversible mutation the actual bounded exploit. If a sibling consumes finite state, inspect preserved responses and pursue only evidence-supported recovery or alternate paths.`,
          `Build a private objective ledger from the supplied task before acting. Do not declare success merely because a flag-shaped value surfaced: satisfy each named transition, chain step, proof action, and safety condition, then make the final proof-producing request and report the literal value.`,
          FAST_STRIKE_LANE_GUIDANCE[laneIndex] ??
            FAST_STRIKE_LANE_GUIDANCE[FAST_STRIKE_LANE_GUIDANCE.length - 1],
        ].join("\n\n"),
        model,
        session,
        target,
        mode: "fast-strike",
        toolProtocol,
        activeTools: [],
        responseSchema: FastStrikeResult,
        ...(session.config?.requireSuccessfulResponse
          ? {
              responseGuard: (result: unknown, { rejectionCount }) => {
                return rejectUnverifiedFastStrikeResponse(result, {
                  exactFlagRequired,
                  minimumVerifiedLayers: requiredVerifiedLayers,
                  requiredDimensions,
                  rejectionCount,
                });
              },
            }
          : {}),
        findingsRegistry,
        subagentId: laneId,
        subagentName: `Fast Strike Lane ${laneIndex + 1}`,
        agentCwd: laneWorkspace,
        authConfig,
        abortSignal: effectiveLaneSignal,
        eventBus,
        onStepFinish,
        enableThinking,
        openAIReasoningEffort,
      });
      try {
        const outcome = normalizeFastStrikeOutcome(await agent.consume(), {
          exactFlagRequired,
          minimumVerifiedLayers: requiredVerifiedLayers,
          requiredDimensions,
        });
        laneOutcomes[laneIndex] = outcome;
        return outcome;
      } catch (error) {
        if (deadlineSignal?.aborted && !laneSignal.aborted) {
          const outcome: FastStrikeOutcome = {
            solved: false,
            summary: `Lane ${laneIndex + 1} reached its bounded ${laneTimeoutMs}ms deadline without verified proof. Preserve target state and checkpoints for the recovery operator; do not treat the deadline as evidence against the remaining hypotheses.`,
          };
          laneOutcomes[laneIndex] = outcome;
          return outcome;
        }
        throw error;
      }
    };
  });

  let strikeResult = await runCompetitiveLanes(
    laneFactories,
    (result) => result.solved,
    abortSignal,
  );

  if (!strikeResult.solved && !abortSignal?.aborted) {
    const recoveryId = "fast-strike-recovery";
    const recoveryWorkspace = join(
      session.rootPath,
      "subagents",
      recoveryId,
      "workspace",
    );
    mkdirSync(recoveryWorkspace, { recursive: true });
    const recoveryAgent = new OffensiveSecurityAgent<FastStrikeOutcome>({
      system: `${FAST_STRIKE_SYSTEM_PROMPT}\n\n${FAST_STRIKE_RECOVERY_PROMPT}`,
      prompt: [
        ...promptParts,
        "The independent lane handoffs follow:",
        buildFastStrikeRecoveryDossier(laneOutcomes),
        `Preserved lane artifacts are under ${join(session.rootPath, "subagents")}. Inspect sibling workspaces, checkpoints, scripts, and captured responses for concrete primitives before repeating discovery.`,
        "Run the bounded recovery pass now. Verify inherited claims against the target, compose compatible primitives, complete every explicit objective clause, and report the exact proof.",
      ].join("\n\n"),
      model,
      session,
      target,
      mode: "fast-strike",
      toolProtocol,
      activeTools: [],
      responseSchema: FastStrikeResult,
      ...(session.config?.requireSuccessfulResponse
        ? {
            responseGuard: (result: unknown, { rejectionCount }) => {
              return rejectUnverifiedFastStrikeResponse(result, {
                exactFlagRequired,
                minimumVerifiedLayers: requiredVerifiedLayers,
                requiredDimensions,
                rejectionCount,
              });
            },
          }
        : {}),
      findingsRegistry,
      subagentId: recoveryId,
      subagentName: "Fast Strike Recovery",
      agentCwd: recoveryWorkspace,
      authConfig,
      abortSignal,
      eventBus,
      onStepFinish,
      enableThinking,
      openAIReasoningEffort,
    });
    strikeResult = normalizeFastStrikeOutcome(await recoveryAgent.consume(), {
      exactFlagRequired,
      minimumVerifiedLayers: requiredVerifiedLayers,
      requiredDimensions,
    });
  }

  if (abortSignal?.aborted) {
    throw new DOMException("Pentest aborted by user", "AbortError");
  }

  await findingsRegistry.groupByRootCause();
  const findings = [...findingsRegistry.getFindings()];

  const report = buildPentestReport(findings, {
    target,
    model,
    sessionId: session.id,
    mode,
  });
  const mdPath = join(session.rootPath, REPORT_FILENAME_MD);
  const jsonPath = join(session.rootPath, REPORT_FILENAME_JSON);
  writeFileSync(mdPath, renderMarkdown(report));
  writeFileSync(jsonPath, renderJson(report));

  eventBus?.emit("workflow-phase-complete", {
    phase: "pentesting",
    summary: {
      findingsCount: findings.length,
      ...(strikeResult
        ? { solved: strikeResult.solved, operatorSummary: strikeResult.summary }
        : {}),
    },
  });

  return {
    findings,
    findingsPath: session.findingsPath,
    pocsPath: session.pocsPath,
    reportPath: mdPath,
  };
}
