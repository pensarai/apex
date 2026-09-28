# TUI performance journeys

Every performance PR should show the workload, baseline and changed revision,
before/after metrics, correctness checks, and measurement limitations. A lower
work count is useful only when it protects correctness or correlates with less
user-visible waiting. Do not gate shared-runner CI on wall-clock milliseconds.

## Run

```sh
bun install --frozen-lockfile
bun run test:tui
bun run perf:tui 5 .cache/tui-baseline.json
```

Run the same command on the candidate revision, writing a different report.
Run base and candidate on the same quiet machine, without concurrent builds or
tests. Repeat in reverse order when interpreting small differences. The optional
JSON path retains every trial; stdout prints the summary. Without a path, stdout
contains the full report. The run count defaults to five and accepts 1 through 30.

## Current fixture

`transcript-typing-v1` mounts the production `MessageList` and `PromptInput` in
OpenTUI's native test renderer, with the real theme, focus, input, and obfuscation
providers. The small host owns input above the transcript, as the dashboard does;
it is not a copy of the dashboard lifecycle. Text updates use the production
`appendStreamedText` projection.

- 100 or 1,000 alternating user/Markdown assistant messages, plus one live tail.
- Eight warm-up keystrokes, then 36 individually dispatched measured keystrokes.
- Either no transcript updates or one update before every fourth keystroke.
- Fixed 100x30 geometry, dark theme, obfuscation off, native render thread off.
- Frozen renderer clock with exactly one explicit frame per action, asserted
  against the renderer's frame ID. Wall-clock measurements remain real-time.
- Every key and streamed tail must appear in the captured character frame.
- After measurement: edit in the middle, resize to 80x24, submit, then paste and
  submit multiline text. Assert exact text and caret-sensitive insertion.
- Always destroy the renderer, including after assertion failures.

The command runs every trial in a fresh Bun subprocess, with an isolated temporary
home, an allowlisted environment, and dotenv loading disabled. No agent is run,
no provider is contacted, and no real session or credential data is used.

## Metrics

| Metric                                 | Meaning                                                                                                                                                               |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Typing/stream to captured frame        | Injection through stdin dispatch, React `act`, an explicit renderer frame, and character-frame capture. Per-trial p75, p95 and maximum, in milliseconds.              |
| Transcript traversals / message visits | Calls to the fixture array's instrumented `map`, executing the native array implementation. Measures production list traversal, not React commits or Markdown parses. |
| CPU milliseconds                       | Process user plus system CPU during the measured replay, excluding initial mount, warm-up, and post-measurement correctness checks.                                   |
| RSS start/end                          | Process resident memory at measured replay boundaries, not peak memory, JS heap, or proof of a leak.                                                                  |

The summary reports the median and range of **per-trial p95s**, not a pooled p95.
Record Bun/OpenTUI/React versions, OS, architecture, CPU, revision, and dirty status
from the report. Compare each workload separately. The tiny array counter is
present in both base and candidate measurements and does not ship with the app.
Positive controls require it to observe mounting and every changed message array;
silently disconnecting the counter must not appear to improve performance.

These are component-level, development-React measurements with explicitly driven
frames, not production terminal latency, renderer FPS, or full-dashboard latency.
Animation, tool rendering, model/network latency, disk persistence, terminal
transport, and automatic frame scheduling are not represented by this fixture.
Do not describe a result here as a whole-application speedup.

## Regression checks and expansion

The pinned-Bun Linux CI replay gates exact interaction correctness and transcript
work ceilings. It does not gate timing, CPU, or RSS. Only lower a work ceiling when
the same fixture still performs and validates the intended interaction.

Add focused fixtures with the optimization they support: tool arguments and
output, swarm subscriptions, cancellation/restart, session restoration, and a
separate real-launch/PTY probe. Keep screenshots and profiles synthetic. Expand
coverage before claiming those journeys are measured; this fixture does not
cover them yet.

## Tool-argument projection

```sh
bun run test src/tui/components/operator-dashboard/tool-arguments.perf.test.ts
```

This adapter-level replay exercises 282 64-character JSON fragments per tool over
a 1,000-message history. It covers synchronous bursts, 4 ms chunk intervals for
one/eight concurrent root tools, and a sparse 40 ms control. Five trials report
actual partial-parser calls, input characters processed, display-sink updates,
process CPU, and wall-clock work duration. Event time is virtual; CPU and work
duration are real. Timing includes fake-clock and spy overhead, excludes module
loading, and is not stream latency or rendering performance. CI asserts exact
work counts, final authoritative arguments, and no pending timers, not timing.

Root argument previews coalesce on a 33 ms timer; additional chunks do not move
its deadline. Final arguments and results remain immediate. Run settlement,
replacement, and full interruption publish pending previews before changing
terminal state; unmount discards them. The message writer updates the recovery
snapshot synchronously rather than waiting for React to commit. Text deltas,
subagent argument streams, canonical model messages, and tool execution are not
throttled. Slow or blocked event loops can exceed the scheduled 33 ms delay.

Use the benchmark-only commit preceding the optimization for an unchanged-source
baseline. Keep absolute values, reduction percentages, slow-stream controls, and
all timing regressions in the PR. Parser-input characters count repeated prefixes,
not network traffic or bytes retained in memory.

## Swarm count subscriptions

```sh
bun --no-env-file scripts/tui-performance/swarm-counts.ts full
bun --no-env-file scripts/tui-performance/swarm-counts.ts counts
bun run test:tui
```

The benchmark-only commit before this optimization supports `full` to reproduce
the unchanged store subscription. The candidate supports both modes, replaying the
same production store/session helpers for 1, 8, and 32 agents. Each agent receives
100 text deltas, 20 tool-argument deltas, and tool start/finalization/result events.
Spawn, completion, failure, interruption, and clear exercise lifecycle delivery.
The replay asserts exact live text, arguments, results, and final statuses.

Report dashboard subscriber callbacks by lifecycle and stream phase, not inferred
React renders. Total callbacks fall from 126/1,001/4,001 to 3/17/65 for the three
workloads (97.62%/98.30%/98.38% reductions). Lifecycle delivery stays at 3/17/65;
stream-only count notifications fall to zero. Full-map subscriptions retain every
notification, keeping the hub/detail views live.

The renderer test mounts the production status bar in a small count-subscribing
host. It checks that streamed content causes no host renders while lifecycle,
clear, restore, and main-agent-moved-on changes update visibility and status text.
It does not mount the full dashboard or test physical-terminal latency. Counts
still scan each new session map; these results do not establish a CPU, memory, or
end-to-end latency improvement. Count callbacks invalidate a snapshot and are not
an exactly-once lifecycle event log.

## Chat scrolling

```sh
bun run perf:tui 5 .cache/scrolling.json scrolling
bun run perf:tui 5 .cache/scrolling-idle.json scrolling-idle
bun run test:tui
```

`transcript-scrolling-v1` uses the production message list and text projection,
100/1,000-message histories, and actual mouse-wheel input. After 16 warm-up
notches, it measures 60 upward and 60 downward notches, with either no updates or
30 interleaved text updates below the viewport. Each notch must move one row.
It reports wheel-to-explicit-frame p95, combined stream/wheel p95, CPU, transcript
traversals, and actual `Renderable.updateFromLayout` calls. The geometry counter
is installed only in the fixture and restored on cleanup. Captures and post-replay
correctness checks are outside the measured loop. There is no physical-terminal
presentation measurement, automatic-frame scheduling, active spinner, or tool-heavy
history in this fixture.

Checks cover the visible history anchor, exact height growth, returning to bottom
by wheel, resuming follow, and wrapped output at 100x30, 80x24, and 40x15. A separate
case starts with an already-tall reply. CI gates these invariants and work ceilings,
not timing. It does not test loading a real persisted session.

Operator/subagent assistant bodies fill the remaining row width. Without that
constraint, OpenTUI 0.1.107 can height-clamp intrinsic text measurement: a reply
growing by 60 rows contributes only 26 rows to the scroll extent at 100x30, moving
history and hiding the end of tall replies. The mixed replay deliberately fails
on the benchmark-only baseline. Use `scrolling-idle` for valid before/after timing;
do not compare timings from a replay that violates scrolling correctness. This
fix does not virtualize history, change wheel acceleration, or remove the existing
history-sized geometry pass.
