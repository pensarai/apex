# Lance

A standardized minimal offensive-capability mode that measures time-to-objective without Apex production assessment workflows.

Lance is an independent mode. Strike remains the focused production research workflow; its tools, prompts, finding policy, and reporting behavior are unchanged.

## Run

In the TUI, open `/advanced`, select **Lance** under **Mode**, choose whether **Finding judge** is enabled, save, and start a new operator session. The selector offers Standard, Strike, and Lance, with the selected mode's explanation below it. Strike and Lance share the independent judge preference; switching modes preserves it. Existing sessions retain their saved settings.

Lance supports multi-turn conversations like Strike. Normal replies and clarification requests return control to the user without declaring the objective unsolved or closing the session. Conversation history is retained on follow-up and resume. `finish_task`, a confirmed complete objective, `finish_unsolved`, and exhausted budgets end the current execution. A new user message starts a new bounded turn in the same conversation; Lance never automatically continues after verification. Sessions closed by earlier Lance builds can be resumed.

With the judge enabled, `submit_objective` sends the evidence and executed PoC to the existing Apex Finding Judge, using the same judge implementation as Strike. The host owns this one verifier; Lance still cannot delegate arbitrary work or launch agents. Rejected evidence returns to Lance; acceptance is terminal after the judge has drained. The result is `judge_accepted`, explicitly distinct from deterministic harness verification. With the judge disabled, no Finding Judge is invoked. Candidate submission records evidence; `finish_task` ends the execution as **completed**, without claiming independent verification.

Programmatic callers opt into the Apex judge with `findingPolicy: "native"`; `"external"` disables it. A supplied `lance.verifyObjective` takes precedence. The CLI uses the saved judge preference; `--external-findings` disables the internal judge. A supplied harness verifier takes precedence.

```sh
bun src/cli.ts pentest --lance --target http://localhost:8080 \
  --prompt 'Extract the challenge flag and submit it as objective evidence.' \
  --model claude-sonnet-4-6 --timeout-ms 900000
```

`--deadline-at <epoch-ms>` lets a harness include process startup in its deadline. Lance rejects combinations with `--fast-strike`, `--task-driven`, or `--threat-model`. Normal authorization and session header configuration still apply.

The public API accepts a trusted harness verifier:

```ts
import { runLance } from "@pensar/apex/core/api";

const { result } = await runLance({
  target,
  prompt: objective,
  model,
  session, // retains scope constraints, credentials, and command safety
  lance: {
    deadlineAt: Date.now() + 900_000,
    verifyObjective: async (candidate, signal) => {
      const verified = await harness.verifyCompleteObjective(
        candidate.evidence,
        signal,
      );
      return { verified, verifierId: "my-objective-verifier-v1" };
    },
  },
});
```

The agent chooses what to investigate, when to pivot, and when it believes the task is complete. `finish_task` takes a concise `summary` and optional `evidence`/`poc`; it closes offensive admission immediately, even if optional verification rejects the claim or fails. A solo operator needs no flag, PoC, or external verifier. Greetings and missing task/target/scope call for a reply or clarification before tools; the working directory is not implicitly in scope.

Apex executes tools, handles completion requests and recovery, and enforces limits. The evaluation platform owns success criteria, milestone validation, and the final evaluation verdict. `submit_objective` checks candidate evidence without requiring the agent to wait for acceptance to finish. A verifier may return `{ verified: true, objectiveComplete: false, verifierId }` for a verified milestone; this does not end a compound task. Only a verified whole objective is terminal. For backward compatibility, a positive verdict omitting `objectiveComplete` means the whole objective. Hosts must keep verifier authority and protected answers outside agent-controlled files and processes.

## Execution policy

`LANCE_CONFIG` pins `lance-v4`, `lance-prompt-v3`, the direct-tool allowlist, a 200-step ceiling, a default 15-minute budget, and a default shutdown reserve of up to 10 seconds (10% for short budgets). Changing the policy or prompt requires a version bump.

Headless execution measures one autonomous attempt. The TUI opts into `lance.interactive`, which measures and bounds each model turn separately, excluding time spent waiting for user input. Interactive turn metrics are explicitly labeled and cannot be used as autonomous workflow-tax measurements.

Available tools are shell execution, HTTP, file inspection/editing, browser interaction, `update_plan`, `finish_task`, `submit_objective`, and `finish_unsolved`. Existing tool implementations preserve scope, credential/header handling, destructive-command checks, and operator approval. Tool calls execute serially so verification cannot race a queued sibling tool into starting afterward.

The harness rejects custom prompts, extra tools, response schemas, child identities, and spawner overrides. Its offensive spawner denies both single-child and fan-out paths. The optional Apex judge is a separately configured host verifier, with its own model usage recorded. Skills, production reporting/documentation, threat-model, persistent memory, workspace integration, job, and completeness tools are absent. The Lance offensive loop disables AI session naming, runtime discovery probes, and model-based tool repair. The optional judge retains the existing Apex judge workflow. No final model summary or report is requested.

### Long-running work

Working memory is available without production assessment workflows:

- **Plan:** `update_plan` replaces a short list of steps and their statuses in one call. An optional explanation can include decisions and scratchpad/evidence paths. Apex saves it as `lance-plan.json` within the session and restores it on resume and after compaction, independently of what the summarizer remembers. It is bounded to 20 steps and never gates completion. Simple requests need no plan.
- **Scratchpad:** ordinary file tools can keep task-local notes and scripts in the writable workspace. Save useful hypotheses, rejected approaches, evidence locations, and next actions. Notes follow the existing file/backend permissions and are not automatically imported from other sessions. This is distinct from the excluded cross-session `add_memory`, `list_memories`, and `get_memory` tools.
- **Context:** the existing Apex context fitter bounds large outputs with retrieval paths; proactive compaction and overflow recovery can summarize the conversation using the same selected model. Compaction has no executable tools, does not delegate, and shares the attempt's deadline and terminal guard. The latest summary replaces previous summaries instead of accumulating them. Saved plan state is appended explicitly. If bounded compaction fails, Lance returns `context_exhausted` rather than restarting from a truncated objective and forgetting progress.

These primitives follow the continuity pattern described in the [Codex compaction guide](https://developers.openai.com/cookbook/examples/gpt-5/codex_prompting_guide#compaction) and [OpenCode tools](https://docs.opencode.ai/docs/tools/#todowrite). Apex uses its provider-neutral summarizer, not Codex's provider-specific encrypted compaction representation. This alignment establishes the intended mechanics; it does not establish optimal thresholds or unchanged solve quality without matched evaluations.

A synchronous terminal latch and shared abort signal guard tool execution and physical provider requests. Confirmation aborts current inference and stops admission immediately. Existing resource disposal and transcript persistence run afterward; these are measured as termination latency. The soft deadline uses the same path, producing `deadline_exhausted` instead of waiting for the external hard kill. A host must supply backends that honor cancellation and allow enough shutdown reserve for its cleanup.

This is an Apex orchestration policy, not a new OS sandbox. Direct shell/browser access retains the existing execution boundary; it is not a security boundary against a malicious program invoking an external model API. Trusted host callbacks and backends must not launch unrecorded auxiliary model work. Same-model context compaction and the explicitly enabled Apex judge are the only supported auxiliary inference paths.

## Results and instrumentation

Each completed attempt or interactive turn writes `lance-result.json` (schema version 1). Interactive turns also append to `lance-turns.jsonl`, preserving earlier turns' measurements. `executionKind` distinguishes `headless_attempt` from `interactive_turn`; ordinary interactive replies have outcome `awaiting_input`. The API adds optional `lance` metadata to `RunAgentResult`; older modes and result fields retain their previous behavior. The CLI emits `LANCE_RESULT:{...}` and the existing `METRICS:{...}` contract. These are agent-side telemetry, not independent proof.

| Field                                             | Meaning                                                                                                                                                                                    |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `configVersion`, `promptVersion`, `promptSha256`  | Reproducible static policy and prompt identity                                                                                                                                             |
| `firstCandidate`                                  | First submitted candidate evidence; elapsed milliseconds and admitted tool count, including submission                                                                                     |
| `firstVerified`                                   | First positive whole-objective verifier response; same clock and counter                                                                                                                   |
| `verificationToTerminationMs`                     | Verification to completed agent drain/cleanup; excludes later host export/upload                                                                                                           |
| `usageBeforeSuccess`                              | Physical requests admitted before verification and their observed tokens/cost                                                                                                              |
| `usage.usageComplete`                             | Whether every admitted request reported usage; interrupted/failed requests can be incomplete                                                                                               |
| `modelSubmittedSuccess`, `harnessVerifiedSuccess` | Separate model claim and callback-confirmed objective                                                                                                                                      |
| `policyViolations`                                | Denied unknown tool calls, child spawning, and attempted work after termination                                                                                                            |
| `outcome`                                         | `completed`, `awaiting_input` (interactive only), `verified`, `judge_accepted`, `unverified`, `unsolved`, `deadline_exhausted`, `step_limit`, `context_exhausted`, `cancelled`, or `error` |

`verificationSource` records `harness`, `apex_judge`, or null. `modelJudgedSuccess` identifies Apex judge acceptance and does not set `harnessVerifiedSuccess`. `usage` and `usageBeforeSuccess` include compaction and the optional judge's requests; `compactionUsage` and `judgeUsage` separately record their requests, tokens, and cost. Failed or interrupted compaction requests remain counted with incomplete usage. Plan and scratchpad tool calls count normally; synthetic compaction display events are not agent tool calls. Existing compaction telemetry retains transformation timing. Compare like verifier settings and configuration versions when measuring workflow tax.

Tokens include the request that produced success. If its usage arrives during drain, it is attributed to the request admitted before verification. Missing usage is never treated as a complete zero-cost request. `costUsd` is null unless the host supplies rates and usage is complete; pricing is per million tokens and separates uncached input, cache reads/writes, and output. An external evaluator can apply its own versioned pricing catalog.

`completion` records the agent's completion summary and timing independently of `verification`. `verificationError` records a failed check without converting the claim to success. `completed` means the agent requested a stop, not that an evaluation passed. `unverified` remains a readable legacy outcome.

`finish_unsolved` and a natural headless model stop without a completion request are non-solves; budget exhaustion is recorded separately. An ordinary interactive reply is not a non-solve. A hard interruption before result persistence is still a harness timeout, not a graceful Lance result.

## External evaluation

An external evaluator can supply `lance.verifyObjective` through the API, or launch the CLI with an inherited Node/Bun JSON IPC channel and `APEX_OBJECTIVE_VERIFIER_IPC=1`. Apex sends `{ id, evidence }`; the parent replies with the matching `id`, `verified`, `verifierId`, optional `objectiveComplete`, and optional `reason`. Keep expected answers and verifier authority in the parent process, outside the agent's filesystem and ordinary tool subprocesses. Agent stdout and success claims are not authoritative verdicts.

Evaluators that grade independently after execution can retain the model's completion request and add their own verdict to the result. Leave in-loop verification times null when no verifier ran during the attempt. Pin the Apex source revision and record the Lance configuration and prompt versions; an older binary or image does not acquire this mode automatically.

Use matched model settings, source revision, challenge, budget, and repeated attempt indices to compare `--lance` with `--fast-strike`. Compare solve rates alongside matched-solve time, tool/request counts, and cost. Total-duration differences estimate workflow overhead; they are not a causal performance result without repeated controlled runs. Existing Strike traces do not gain retroactive time-to-objective measurements.
