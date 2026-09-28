# Home idle animation: one update per tick, paused while blurred

`src/tui/components/chat/petri-animation.tsx` previously performed two state
updates per animation tick (a tick-state update feeding an effect that stored
the next frame) and kept ticking while the terminal was blurred. It now
performs one state update per tick from a component-owned interval and
suspends that interval while the terminal reports blur, resuming on refocus.
The wave simulation, gradient, and row indexing are unchanged: every active
frame still costs O(width × height); the change removes the second update
per tick and all steady animation work while blurred.

`src/tui/terminal-focus.ts` tracks the renderer's reported focus state per
renderer (`WeakMap`, cleared with the seam's renderer listeners) and exports
`getTerminalFocusState`. The always-mounted terminal focus seam records it,
so a mount that happens while already blurred starts paused, focus changes
while the animation is unmounted are kept, and no state crosses renderer
lifetimes. The renderer itself emits `focus`/`blur` on the bracketed focus
escapes it parses; there is no public current-state getter.

## Regression gates

`scripts/tui-performance/petri-animation.bun.test.tsx` (bun test, part of
`bun run test:tui`) drives the real renderer via `testRender` with fake
timers and real focus escape sequences through stdin parsing:

- exactly one React update per animation tick and exact frame rows and
  gradient colors at a deterministic simulation time,
- frozen frame and zero updates while blurred (transition, typing, resize,
  and theme repaints excluded and separately asserted),
- mount while already blurred renders the frozen time-zero frame and
  resumes on refocus; focus changes while unmounted are captured; remount
  resumes immediately,
- prompt typing, caret, and submit keep working across blur/refocus, and the
  animation owns exactly one focus/blur listener of each kind plus its
  interval, released on unmount while the renderer stays alive; renderer
  independence (a second renderer does not inherit the first's blur),
- no leaked timers or process listeners after destroy.

## Production PTY benchmark

```sh
python3 scripts/performance/petri-idle-driver.py BASELINE CANDIDATE PAIRS OUT_DIR
```

The driver runs the real TUI entry (`scripts/performance/petri-idle-run.ts`,
which only samples whole-process `process.cpuUsage` with actual interval
start/end/wall stamps) in a 120×35 PTY through warm, focused, blurred
(transition, steady, typing, resize, restore), refocused, and providers-dialog
phases, alternating fresh processes per side. The in-process sampler records
one absolute CPU snapshot per interval retained as the next baseline, so the
log write's own cost lands in the following interval. Per-phase CPU includes
only sample intervals lying wholly inside the phase window and divides by
those samples' actual wall durations.

Labels are honest by design: PTY read counts and byte rates are transport
chunks, not renderer frames. `providersDialogIdle` includes ~1 s of command
entry before the 8 s dialog pump and opens a dialog over the still-mounted
home view — no non-home timing claim. Every run strips inherited provider API
keys, isolates `HOME`, selects a dead local model endpoint, and records
per-side git heads plus animation/seam/runner/driver hashes, `NODE_ENV`,
Bun version, and child cleanup. The driver fails loudly on a missing home or
dialog anchor, child exit, a steady phase with no accepted CPU intervals, or
failed input continuity.

Local numbers establish the waste and its removal on this fixture — focused
CPU savings vary; the reliable win is eliminating steady blurred animation
work. They are not a deployed-binary or battery-life claim.
