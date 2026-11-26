import {
  newQuickJSWASMModule,
  QuickJSContext,
  QuickJSRuntime,
  type QuickJSWASMModule,
} from "quickjs-emscripten";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { AgentEventBus } from "../eventBus";
import { CanonicalCapabilityInvoker } from "./capabilityInvoker";

vi.mock("quickjs-emscripten", async (importOriginal) => {
  const actual = await importOriginal<typeof import("quickjs-emscripten")>();
  return {
    ...actual,
    newQuickJSWASMModule: vi.fn(actual.newQuickJSWASMModule),
  };
});

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
});
afterEach(() => vi.restoreAllMocks());

async function createRuntime() {
  const { CodeModeRuntime } = await import("./runtime");
  const onComplete = vi.fn();
  const invoker = new CanonicalCapabilityInvoker({
    tools: {},
    allowedTools: [],
    eventBus: new AgentEventBus(),
    sessionId: "session_setup",
    getMessageId: () => "message_setup",
  });
  return { runtime: new CodeModeRuntime(invoker, [], onComplete), onComplete };
}

const context = { parentToolCallId: "exec_setup", messages: [] };

describe("code cell setup failures", () => {
  test.each([
    0, 1,
  ])("waits for termination during module setup even with a %s ms yield", async (yieldTimeMs) => {
    const { newQuickJSWASMModule: loadModule } =
      await vi.importActual<typeof import("quickjs-emscripten")>(
        "quickjs-emscripten",
      );
    let resumeLoad = () => {};
    vi.mocked(newQuickJSWASMModule).mockImplementationOnce(
      (...args) =>
        new Promise((resolve) => {
          resumeLoad = () => {
            resumeLoad = () => {};
            resolve(loadModule(...args));
          };
        }),
    );
    const { runtime, onComplete } = await createRuntime();
    try {
      const cell = await runtime.execute("text(1)", context, 0);
      expect(cell.status).toBe("running");
      const stopped = runtime.wait(cell.cellId, {
        terminate: true,
        yieldTimeMs,
      });
      await new Promise((resolve) => setTimeout(resolve, 10));
      resumeLoad();
      const result = await stopped;
      expect(result.status).toBe("terminated");
      expect(onComplete).toHaveBeenCalledWith(result);
      await expect(runtime.wait(cell.cellId)).rejects.toThrow(
        "Unknown or completed",
      );
    } finally {
      resumeLoad();
      await runtime.dispose();
    }
  });

  test("returns a failed cell after a yielded module load fails and allows a retry", async () => {
    let rejectLoad: (error: Error) => void = () => {};
    vi.mocked(newQuickJSWASMModule).mockImplementationOnce(
      () =>
        new Promise<QuickJSWASMModule>((_, reject) => {
          rejectLoad = reject;
        }),
    );
    const { runtime, onComplete } = await createRuntime();
    try {
      const pending = await runtime.execute("text(1)", context, 0);
      expect(pending.status).toBe("running");
      rejectLoad(new Error("WASM load failed"));
      const failed = await runtime.wait(pending.cellId);
      expect(failed).toMatchObject({
        status: "failed",
        output: "WASM load failed",
      });
      expect(onComplete).toHaveBeenCalledWith(failed);
      const retry = await runtime.execute("text(42)", {
        ...context,
        parentToolCallId: "exec_retry",
      });
      expect(retry).toMatchObject({ status: "completed", output: "42" });
      expect(newQuickJSWASMModule).toHaveBeenCalledTimes(2);
    } finally {
      await runtime.dispose();
    }
  });

  test.each([
    "setMemoryLimit",
    "newContext",
  ] as const)("disposes the runtime when %s fails", async (method) => {
    const disposed = vi.spyOn(QuickJSRuntime.prototype, "dispose");
    vi.spyOn(QuickJSRuntime.prototype, method).mockImplementationOnce(() => {
      throw new Error("runtime setup failed");
    });
    const { runtime, onComplete } = await createRuntime();
    try {
      const failed = await runtime.execute("text(1)", context);
      expect(failed).toMatchObject({
        status: "failed",
        output: "runtime setup failed",
      });
      expect(disposed).toHaveBeenCalledOnce();
      expect(onComplete).toHaveBeenCalledWith(failed);
    } finally {
      await runtime.dispose();
    }
  });

  test("releases host handles, context, and runtime after host-function registration fails", async () => {
    const disposedRuntime = vi.spyOn(QuickJSRuntime.prototype, "dispose");
    const disposedContext = vi.spyOn(QuickJSContext.prototype, "dispose");
    vi.spyOn(QuickJSContext.prototype, "setProp").mockImplementationOnce(() => {
      throw new Error("host registration failed");
    });
    const { runtime, onComplete } = await createRuntime();
    try {
      const failed = await runtime.execute("text(1)", context);
      expect(failed).toMatchObject({
        status: "failed",
        output: "host registration failed",
      });
      expect(disposedContext).toHaveBeenCalledOnce();
      expect(disposedRuntime).toHaveBeenCalledOnce();
      expect(onComplete).toHaveBeenCalledWith(failed);
      const next = await runtime.execute("text(42)", {
        ...context,
        parentToolCallId: "exec_after_setup_failure",
      });
      expect(next).toMatchObject({ status: "completed", output: "42" });
    } finally {
      await runtime.dispose();
    }
  });
});
