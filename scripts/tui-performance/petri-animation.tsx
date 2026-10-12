import { jest } from "bun:test";
import assert from "node:assert/strict";
import { type CliRenderer, RGBA } from "@opentui/core";
import { testRender } from "@opentui/react/test-utils";
import { act, Profiler, useState } from "react";
import { WaveSimulation } from "../../src/tui/components/chat/lib/wave-simulation";
import { PetriAnimation } from "../../src/tui/components/chat/petri-animation";
import {
  PromptInput,
  type PromptInputRef,
} from "../../src/tui/components/shared/prompt-input";
import { TerminalFocusHandler } from "../../src/tui/components/terminal-focus-handler";
import { TerminalDimensionsProvider } from "../../src/tui/context/dimensions";
import { FocusProvider } from "../../src/tui/context/focus";
import { InputProvider } from "../../src/tui/context/input";
import { ObfuscationProvider } from "../../src/tui/context/obfuscation";
import { getTerminalFocusState } from "../../src/tui/terminal-focus";
import type { ColorMode } from "../../src/tui/theme";
import {
  registerBuiltinThemes,
  ThemeProvider,
  useTheme,
} from "../../src/tui/theme";

const WIDTH = 40;
const HEIGHT = 16;
const HEIGHT_FRACTION = 0.5;
const RESIZED_WIDTH = 60;
const RESIZED_HEIGHT = 20;
const TAU = 1000;

// Independent reimplementation of the component's documented gradient and
// row-indexing spec, so drift in the shipped colors or indexing fails here.
function referenceGradient(base: RGBA, steps = 9): RGBA[] {
  const r = base.r * 255;
  const g = base.g * 255;
  const b = base.b * 255;
  return Array.from({ length: steps }, (_, i) => {
    const t = steps === 1 ? 1 : i / (steps - 1);
    const brightness = 0.35 + t * 1.25;
    return RGBA.fromInts(
      Math.min(255, Math.round(r * brightness + t * 25)),
      Math.min(255, Math.round(g * brightness)),
      Math.min(255, Math.round(b * brightness + t * 10)),
      255,
    );
  });
}

function referenceGradientIndex(rowIdx: number, totalRows: number) {
  const progress = rowIdx / Math.max(1, totalRows - 1);
  return Math.min(Math.floor(progress * 8), 8);
}

function expectedRows(width: number, height: number, time: number): string[] {
  const simulation = new WaveSimulation(width, height);
  for (let i = 0; i < time; i++) simulation.step();
  return simulation.render();
}

interface FixtureHandles {
  commits: string[];
  setMode: (mode: ColorMode) => void;
  setShowPetri: (show: boolean) => void;
}

// Mirrors production: the always-mounted terminal focus seam tracks the
// renderer's reported focus state, and the home animation is conditional.
function Fixture({
  initialShowPetri,
  handles,
}: {
  initialShowPetri: boolean;
  handles: FixtureHandles;
}) {
  const { colors, setMode } = useTheme();
  const [showPetri, setShowPetri] = useState(initialShowPetri);
  handles.setMode = setMode;
  handles.setShowPetri = setShowPetri;
  return (
    <box width="100%" height="100%" flexDirection="column">
      {showPetri ? (
        <PetriAnimation height={HEIGHT_FRACTION} width="100%" />
      ) : null}
      <box flexDirection="row">
        {referenceGradient(colors.primary).map((color, k) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: fixed nine-step gradient cells, never reorder
          <text key={k} fg={color} content="A" />
        ))}
      </box>
    </box>
  );
}

const RENDERER_OPTIONS = {
  useThread: false,
  screenMode: "alternate-screen",
  exitOnCtrlC: false,
  clock: {
    now: () => 0,
    setTimeout: () => 0,
    clearTimeout: () => {},
    setInterval: () => 0,
    clearInterval: () => {},
  },
} as const;

interface FixtureSetup {
  renderer: CliRenderer;
  mockInput: {
    pressKey: (key: string) => void;
    pressArrow: (direction: string) => void;
    pressEnter: () => void;
  };
  renderOnce: () => Promise<void>;
  captureCharFrame: () => string;
  resize: (width: number, height: number) => void;
}

async function mountFixture(
  initialShowPetri: boolean,
  handles: FixtureHandles,
): Promise<FixtureSetup> {
  registerBuiltinThemes();
  const commits: string[] = [];
  handles.commits = commits;
  const setup = await testRender(
    <ThemeProvider initialMode="dark">
      <TerminalDimensionsProvider>
        <FocusProvider>
          <TerminalFocusHandler />
          <Profiler
            id="petri"
            onRender={(_id, phase) => {
              commits.push(phase);
            }}
          >
            <Fixture initialShowPetri={initialShowPetri} handles={handles} />
          </Profiler>
        </FocusProvider>
      </TerminalDimensionsProvider>
    </ThemeProvider>,
    { width: WIDTH, height: HEIGHT, ...RENDERER_OPTIONS },
  );
  return setup as unknown as FixtureSetup;
}

interface Harness {
  updateCount: () => number;
  tick: (ms?: number) => Promise<void>;
  input: (key: string) => Promise<void>;
  render: () => Promise<void>;
  rows: () => string[];
  fg: (x: number, y: number) => number[];
  referenceFg: (y: number) => number[][];
}

function buildHarness(setup: FixtureSetup, commits: string[]): Harness {
  const { renderer, mockInput, renderOnce, captureCharFrame } = setup;
  const fgChannels = (x: number, y: number) => {
    const buffer = renderer.currentRenderBuffer.buffers.fg;
    const base = (y * renderer.terminalWidth + x) * 4;
    return [buffer[base], buffer[base + 1], buffer[base + 2], buffer[base + 3]];
  };
  return {
    updateCount: () => commits.filter((p) => p === "update").length,
    tick: async (ms = 50) => {
      await act(async () => {
        jest.advanceTimersByTime(ms);
        await new Promise<void>((resolve) => setImmediate(resolve));
      });
    },
    input: async (key: string) => {
      await act(async () => {
        mockInput.pressKey(key);
        await new Promise<void>((resolve) => setImmediate(resolve));
      });
    },
    render: () => act(renderOnce),
    rows: () => captureCharFrame().split("\n"),
    fg: fgChannels,
    referenceFg: (y) => Array.from({ length: 9 }, (_, k) => fgChannels(k, y)),
  };
}

// The real terminal streams must not receive the seam's escape writes while
// the production seam runs under the test renderer.
function isolateRealStreams() {
  const stdout = process.stdout as { isTTY?: boolean };
  const stdin = process.stdin as { isTTY?: boolean };
  const stdoutTty = stdout.isTTY;
  const stdinTty = stdin.isTTY;
  stdout.isTTY = false;
  stdin.isTTY = false;
  return () => {
    stdout.isTTY = stdoutTty;
    stdin.isTTY = stdinTty;
  };
}

// Isolation and fake timers span mount through destroy: the seam's escape
// writes and the animation's interval both happen inside. The renderer is
// torn down while fake timers still own scheduling, and the outer finally
// restores real time and the TTY flags even when mount or teardown rejects.
async function withTestHarness(
  mount: () => Promise<FixtureSetup>,
  fn: (setup: FixtureSetup) => Promise<void>,
) {
  const restoreStreams = isolateRealStreams();
  try {
    jest.useFakeTimers();
    let setup: FixtureSetup | null = null;
    try {
      setup = await mount();
      await fn(setup);
    } finally {
      const mounted = setup;
      if (mounted && !mounted.renderer.isDestroyed) {
        await act(() => {
          mounted.renderer.destroy();
        });
      }
    }
  } finally {
    jest.useRealTimers();
    restoreStreams();
  }
}

export async function runPetriIdleJourney() {
  const handles: FixtureHandles = {
    commits: [],
    setMode: () => {},
    setShowPetri: () => {},
  };
  const initialRows = Math.floor(HEIGHT * HEIGHT_FRACTION);
  const resizedRows = Math.floor(RESIZED_HEIGHT * HEIGHT_FRACTION);

  await withTestHarness(
    () => mountFixture(true, handles),
    async (setup) => {
      const harness = buildHarness(setup, handles.commits);
      const { renderer } = setup;
      assert.equal(getTerminalFocusState(renderer), null);
      await harness.render();
      const atMount = harness.updateCount();
      await harness.tick(0);
      assert.equal(
        harness.updateCount(),
        atMount,
        "no updates before first tick",
      );

      // One state update per animation tick.
      await harness.tick();
      assert.equal(harness.updateCount(), atMount + 1, "one update per tick");
      await harness.tick();
      assert.equal(harness.updateCount(), atMount + 2, "one update per tick");
      for (let i = 0; i < 10; i++) {
        await harness.tick();
      }
      assert.equal(
        harness.updateCount(),
        atMount + 12,
        "exactly one update per tick across twelve ticks",
      );

      // Exact visual and color behavior at a deterministic time (12 steps).
      await harness.render();
      assert.deepEqual(
        harness.rows().slice(0, initialRows),
        expectedRows(WIDTH, initialRows, 12),
        "animation rows must match the simulation exactly",
      );
      const referenceFg = harness.referenceFg(initialRows);
      for (let row = 0; row < initialRows; row++) {
        const expected = referenceFg[referenceGradientIndex(row, initialRows)];
        for (const col of [1, WIDTH / 2, WIDTH - 2]) {
          assert.deepEqual(
            harness.fg(col, row),
            expected,
            `row ${row} col ${col} must use its gradient color`,
          );
        }
      }

      // Blur: the blur transition itself commits once, then nothing.
      await harness.input("\x1b[O");
      assert.equal(getTerminalFocusState(renderer), false);
      const atBlur = harness.updateCount();
      const rowsAtBlur = harness.rows();
      await harness.tick(TAU);
      assert.equal(
        harness.updateCount(),
        atBlur,
        "no steady animation updates while blurred",
      );
      await harness.render();
      assert.deepEqual(
        harness.rows(),
        rowsAtBlur,
        "frame must be frozen while blurred",
      );

      // Resize while blurred: exactly the resize repaint, no stepping.
      await act(async () => {
        setup.resize(RESIZED_WIDTH, RESIZED_HEIGHT);
        await new Promise<void>((resolve) => setImmediate(resolve));
      });
      const atResize = harness.updateCount();
      await harness.tick(TAU);
      assert.equal(
        harness.updateCount(),
        atResize,
        "resize repaint must not resume ticking",
      );
      await harness.render();
      const resizedFrame = harness.rows().slice(0, resizedRows);
      assert.equal(
        resizedFrame.length,
        resizedRows,
        "frame must use new row count",
      );
      assert.ok(
        resizedFrame[0].length >= RESIZED_WIDTH - 1,
        "frame must use the new width",
      );
      assert.deepEqual(
        resizedFrame,
        expectedRows(RESIZED_WIDTH, resizedRows, 12),
        "resized frame must match the simulation at frozen time",
      );

      // Theme change while blurred: colors follow the new theme, no stepping.
      const darkRowColor = harness.fg(2, 3);
      await act(() => {
        handles.setMode("light");
      });
      await harness.render();
      assert.equal(
        harness.rows().slice(0, resizedRows).join(""),
        resizedFrame.join(""),
        "theme change must not step the simulation",
      );
      const lightReferenceFg = harness.referenceFg(resizedRows);
      assert.notDeepEqual(
        lightReferenceFg[referenceGradientIndex(3, resizedRows)],
        darkRowColor,
        "sanity: light gradient must differ from dark",
      );
      assert.deepEqual(
        harness.fg(2, 3),
        lightReferenceFg[referenceGradientIndex(3, resizedRows)],
        "blurred theme change must repaint with the new gradient",
      );

      // Refocus: animation resumes at the very next tick.
      const atRefocus = harness.updateCount();
      await harness.input("\x1b[I");
      assert.equal(getTerminalFocusState(renderer), true);
      await harness.tick();
      assert.equal(
        harness.updateCount(),
        atRefocus + 2,
        "refocus commits once and the next tick once",
      );
      await harness.render();
      assert.deepEqual(
        harness.rows().slice(0, resizedRows),
        expectedRows(RESIZED_WIDTH, resizedRows, 13),
        "refocused frame must advance the simulation one step",
      );

      // Unmount: the owned interval is released.
      const pendingBeforeDestroy = jest.getTimerCount();
      assert.ok(
        pendingBeforeDestroy >= 1,
        "sanity: interval pending before destroy",
      );
      await act(() => {
        renderer.destroy();
      });
      assert.equal(
        jest.getTimerCount(),
        0,
        "destroy must clear the animation interval and leave no timers",
      );
    },
  );

  return {
    fixture: "petri-idle-v1",
    dimensions: { width: WIDTH, height: HEIGHT },
    resized: { width: RESIZED_WIDTH, height: RESIZED_HEIGHT },
    commitsPerTick: 1,
    blurredTicks: TAU / 50,
    blurredUpdates: 0,
    pendingTimersAfterDestroy: 0,
    assertions:
      "updates per tick, exact rows and gradient colors, frozen blur, resize while blurred, theme while blurred, refocus, unmount",
  };
}

export async function runPetriMountWhileBlurredJourney() {
  const handles: FixtureHandles = {
    commits: [],
    setMode: () => {},
    setShowPetri: () => {},
  };
  const animationRows = Math.floor(HEIGHT * HEIGHT_FRACTION);

  await withTestHarness(
    () => mountFixture(false, handles),
    async (setup) => {
      const harness = buildHarness(setup, handles.commits);
      const { renderer } = setup;
      await harness.render();
      // The renderer reports blur before the animation ever mounts; the seam
      // records it even with the animation absent.
      await harness.input("\x1b[O");
      assert.equal(getTerminalFocusState(renderer), false);
      await act(() => {
        handles.setShowPetri(true);
      });
      await harness.render();
      const atMount = harness.updateCount();

      // Mounted while blurred: a frozen time-zero frame, never stepped.
      assert.deepEqual(
        harness.rows().slice(0, animationRows),
        expectedRows(WIDTH, animationRows, 0),
        "mount while blurred must paint the time-zero frame",
      );
      await harness.tick(TAU);
      assert.equal(
        harness.updateCount(),
        atMount,
        "animation mounted while blurred must not animate",
      );
      assert.deepEqual(
        harness.rows().slice(0, animationRows),
        expectedRows(WIDTH, animationRows, 0),
        "frame must stay frozen at time zero while blurred",
      );

      // Refocus: ticking starts at the next tick from time zero.
      await harness.input("\x1b[I");
      await harness.tick();
      assert.equal(
        harness.updateCount(),
        atMount + 2,
        "refocus must start the animation at the next tick",
      );
      await harness.render();
      assert.deepEqual(
        harness.rows().slice(0, animationRows),
        expectedRows(WIDTH, animationRows, 1),
        "first focused frame must match the first simulation step",
      );
    },
  );

  return { fixture: "petri-mount-blurred-v1", blurredUpdates: 0 };
}

export async function runPetriUnmountedFocusChangeJourney() {
  const handles: FixtureHandles = {
    commits: [],
    setMode: () => {},
    setShowPetri: () => {},
  };
  const animationRows = Math.floor(HEIGHT * HEIGHT_FRACTION);

  await withTestHarness(
    () => mountFixture(true, handles),
    async (setup) => {
      const harness = buildHarness(setup, handles.commits);
      const { renderer } = setup;
      await harness.render();
      await harness.input("\x1b[O");
      await harness.tick();

      // Unmount the animation, then refocus while it is absent: the seam
      // must still record the change.
      await act(() => {
        handles.setShowPetri(false);
      });
      await harness.input("\x1b[I");
      assert.equal(getTerminalFocusState(renderer), true);
      await harness.tick(TAU);
      await act(() => {
        handles.setShowPetri(true);
      });
      await harness.render();
      const atRemount = harness.updateCount();
      await harness.tick();
      assert.equal(
        harness.updateCount(),
        atRemount + 1,
        "remount after an unmounted refocus must animate immediately",
      );
      await harness.render();
      assert.deepEqual(
        harness.rows().slice(0, animationRows),
        expectedRows(WIDTH, animationRows, 1),
        "remounted animation must step from a fresh simulation",
      );
    },
  );

  return { fixture: "petri-unmounted-focus-v1", remountedUpdates: 1 };
}

export async function runPetriRendererIndependenceJourney() {
  const animationRows = Math.floor(HEIGHT * HEIGHT_FRACTION);

  const firstHandles: FixtureHandles = {
    commits: [],
    setMode: () => {},
    setShowPetri: () => {},
  };
  await withTestHarness(
    () => mountFixture(true, firstHandles),
    async (setup) => {
      const harness = buildHarness(setup, firstHandles.commits);
      await harness.render();
      await harness.input("\x1b[O");
      assert.equal(getTerminalFocusState(setup.renderer), false);
    },
  );

  // A second renderer in the same process starts fresh, not paused.
  const secondHandles: FixtureHandles = {
    commits: [],
    setMode: () => {},
    setShowPetri: () => {},
  };
  await withTestHarness(
    () => mountFixture(true, secondHandles),
    async (setup) => {
      const harness = buildHarness(setup, secondHandles.commits);
      assert.equal(getTerminalFocusState(setup.renderer), null);
      await harness.render();
      const atMount = harness.updateCount();
      await harness.tick();
      assert.equal(
        harness.updateCount(),
        atMount + 1,
        "a fresh renderer must not inherit the previous renderer's blur",
      );
      await harness.render();
      assert.deepEqual(
        harness.rows().slice(0, animationRows),
        expectedRows(WIDTH, animationRows, 1),
        "fresh renderer animation must run from time zero",
      );
    },
  );

  return { fixture: "petri-renderer-independence-v1" };
}

interface InputFixtureHandles {
  setVisible: (value: boolean) => void;
}

// The prompt lives beside the conditional animation, as on the home screen.
function InputFixture({
  handles,
  promptRef,
  submissions,
}: {
  handles: InputFixtureHandles;
  promptRef: { current: PromptInputRef | null };
  submissions: string[];
}) {
  const [visible, setVisibleState] = useState(false);
  handles.setVisible = setVisibleState;
  return (
    <box width="100%" height="100%" flexDirection="column">
      {visible ? <PetriAnimation height={0.4} width="100%" /> : null}
      <box height={3} flexShrink={0}>
        <PromptInput
          ref={(value) => {
            promptRef.current = value;
          }}
          focused
          onSubmit={(value) => {
            submissions.push(value);
          }}
        />
      </box>
    </box>
  );
}

export async function runPetriInputResourceJourney() {
  const submissions: string[] = [];
  const promptRef: { current: PromptInputRef | null } = { current: null };
  const handles: InputFixtureHandles = {
    setVisible: () => {},
  };
  const originalStep = WaveSimulation.prototype.step;
  let steps = 0;
  // Count simulation steps without instrumenting shipped component code.
  WaveSimulation.prototype.step = function countsStep(this: WaveSimulation) {
    steps++;
    return originalStep.call(this);
  };
  const processListeners = {
    sigcont: process.listenerCount("SIGCONT"),
    data: process.stdin.listenerCount("data"),
  };

  try {
    await withTestHarness(
      async () => {
        registerBuiltinThemes();
        const setup = await testRender(
          <ThemeProvider initialMode="dark">
            <ObfuscationProvider initialEnabled={false}>
              <TerminalDimensionsProvider>
                <FocusProvider>
                  <TerminalFocusHandler />
                  <InputProvider>
                    <InputFixture
                      handles={handles}
                      promptRef={promptRef}
                      submissions={submissions}
                    />
                  </InputProvider>
                </FocusProvider>
              </TerminalDimensionsProvider>
            </ObfuscationProvider>
          </ThemeProvider>,
          { width: 80, height: 24, ...RENDERER_OPTIONS },
        );
        return setup as unknown as FixtureSetup;
      },
      async (setup) => {
        const { renderer, mockInput, renderOnce } = setup;
        const turn = async (action?: () => unknown) => {
          await act(async () => {
            action?.();
            await new Promise<void>((resolve) => setImmediate(resolve));
          });
          await act(renderOnce);
        };
        const tick = (ms = 50) => turn(() => jest.advanceTimersByTime(ms));
        const counts = () => ({
          blur: renderer.listenerCount("blur"),
          focus: renderer.listenerCount("focus"),
          timers: jest.getTimerCount(),
        });

        await turn(() => promptRef.current?.focus());
        await tick(20);
        const absent = counts();

        // Adding only the animation owns exactly one listener of each kind and
        // one interval.
        await turn(() => handles.setVisible(true));
        const mounted = counts();
        assert.equal(mounted.blur, absent.blur + 1);
        assert.equal(mounted.focus, absent.focus + 1);
        assert.equal(mounted.timers, absent.timers + 1);
        await tick();
        assert.equal(steps, 1);
        for (const character of "ab") {
          await turn(() => mockInput.pressKey(character));
          await tick();
        }
        assert.ok(promptRef.current, "prompt must mount");
        const prompt = promptRef.current;
        assert.equal(prompt.getValue(), "ab");

        // Blur freezes the simulation; repeated reports stay paused.
        await turn(() => mockInput.pressKey("\x1b[O"));
        assert.equal(getTerminalFocusState(renderer), false);
        const pausedAt = steps;
        await tick(TAU);
        assert.equal(steps, pausedAt, "simulation must not step while blurred");
        await turn(() => mockInput.pressKey("\x1b[O"));
        await tick(TAU);
        assert.equal(steps, pausedAt, "repeated blur reports must stay paused");
        assert.equal(
          prompt.getValue(),
          "ab",
          "focus escapes cannot enter prompt text",
        );

        // Refocus resumes ticking; typing, caret, and submit still work.
        await turn(() => mockInput.pressKey("\x1b[I"));
        await tick();
        assert.equal(steps, pausedAt + 1);
        await turn(() => mockInput.pressArrow("left"));
        await turn(() => mockInput.pressKey("X"));
        assert.equal(
          prompt.getValue(),
          "aXb",
          "caret position must survive blur/refocus",
        );
        await turn(() => mockInput.pressEnter());
        assert.deepEqual(
          submissions,
          ["aXb"],
          "submission must be exact after ticks/refocus",
        );
        await tick(20);

        // Hiding only the animation returns exactly the app's resource counts.
        await turn(() => handles.setVisible(false));
        assert.deepEqual(
          counts(),
          absent,
          "Petri unmount must release only its resources",
        );
        const afterHide = steps;
        await tick(TAU);
        assert.equal(steps, afterHide);

        // Blur while absent, then mount while paused: no animation interval.
        await turn(() => mockInput.pressKey("\x1b[O"));
        await turn(() => handles.setVisible(true));
        assert.equal(counts().timers, absent.timers);
        await tick(TAU);
        assert.equal(steps, afterHide);
        await turn(() => handles.setVisible(false));
        assert.deepEqual(counts(), absent);

        await act(() => {
          renderer.destroy();
        });
        assert.equal(jest.getTimerCount(), 0);
        assert.equal(
          process.listenerCount("SIGCONT"),
          processListeners.sigcont,
          "destroy must remove the seam's SIGCONT listener",
        );
        assert.equal(
          process.stdin.listenerCount("data"),
          processListeners.data,
          "destroy must remove the seam's stdin listener",
        );
      },
    );
  } finally {
    WaveSimulation.prototype.step = originalStep;
  }

  return {
    fixture: "petri-input-resource-v1",
    steps,
    submissions,
    pendingTimersAfterDestroy: 0,
  };
}

if (import.meta.main) {
  const summary = await runPetriIdleJourney();
  process.stdout.write(`${JSON.stringify(summary)}\n`);
}
