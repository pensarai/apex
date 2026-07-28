import { randomUUID } from "node:crypto";
import type { ModelMessage } from "ai";
import { getQuickJS } from "quickjs-emscripten";
import type {
  CanonicalCapabilityInvoker,
  CodeModeCellMetrics,
} from "./capabilityInvoker";

const DEFAULT_YIELD_MS = 10_000;
const MAX_YIELD_MS = 60_000;
const MAX_CELL_RUNTIME_MS = 30 * 60 * 1000;
const MAX_CPU_SLICE_MS = 2_000;
const DISPOSE_GRACE_MS = 5_000;
const MEMORY_LIMIT_BYTES = 64 * 1024 * 1024;
const MAX_OUTPUT_CHARS = 30_000;

export type CodeCellStatus = "completed" | "failed" | "running" | "terminated";

export type CodeCellResult = {
  cellId: string;
  status: CodeCellStatus;
  output: string;
  metrics?: CodeModeCellMetrics & { durationMs: number };
  guidance?: string[];
};

type ExecutionContext = {
  parentToolCallId: string;
  messages: ModelMessage[];
  abortSignal?: AbortSignal;
};

type Cell = {
  controller: AbortController;
  promise: Promise<CodeCellResult>;
};

function truncateOutput(value: string): string {
  if (value.length <= MAX_OUTPUT_CHARS) return value;
  return `${value.slice(0, MAX_OUTPUT_CHARS)}\n...[code-mode output truncated]`;
}

function serializeOutput(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function combineSignals(local: AbortSignal, parent?: AbortSignal): AbortSignal {
  return parent ? AbortSignal.any([local, parent]) : local;
}

const GUEST_PRELUDE = `
(() => {
  const invoke = async (name, input = {}) => {
    const encoded = await __apexInvoke(name, JSON.stringify(input));
    return JSON.parse(encoded);
  };
  const shell = (input) => invoke("execute_command", input);
  const browser = Object.freeze({
    navigate: (input) => invoke("browser_navigate", input),
    snapshot: (input) => invoke("browser_snapshot", input),
    screenshot: (input) => invoke("browser_screenshot", input),
    click: (input) => invoke("browser_click", input),
    fill: (input) => invoke("browser_fill", input),
    evaluate: (input) => invoke("browser_evaluate", input),
    console: (input) => invoke("browser_console", input),
    getCookies: (input) => invoke("browser_get_cookies", input),
  });
  globalThis.tools = Object.freeze({
    call: invoke,
    shell,
    process: Object.freeze({ exec: shell }),
    findings: Object.freeze({
      document: (input) => invoke("document_vulnerability", input),
    }),
    checkpoint: Object.freeze({
      record: (input) => invoke("checkpoint_state", input),
    }),
    response: Object.freeze({
      submit: (result) => invoke("response", { result }),
    }),
    browser,
  });
  globalThis.ALL_TOOLS = Object.freeze([
    "execute_command",
    "document_vulnerability",
    "checkpoint_state",
    "response",
    "browser_navigate",
    "browser_snapshot",
    "browser_screenshot",
    "browser_click",
    "browser_fill",
    "browser_evaluate",
    "browser_console",
    "browser_get_cookies",
  ]);
  globalThis.text = (value) => __apexText(JSON.stringify(value));
  globalThis.store = (key, value) => __apexStore(key, JSON.stringify(value));
  globalThis.load = (key) => {
    const value = __apexLoad(key);
    return value === undefined ? undefined : JSON.parse(value);
  };
  const runLimited = async (items, concurrency, worker, settle) => {
    if (!Array.isArray(items)) throw new TypeError("items must be an array");
    if (!Number.isInteger(concurrency) || concurrency < 1) {
      throw new TypeError("concurrency must be a positive integer");
    }
    const results = new Array(items.length);
    let nextIndex = 0;
    const lane = async () => {
      while (nextIndex < items.length) {
        const index = nextIndex++;
        if (settle) {
          try {
            results[index] = {
              status: "fulfilled",
              value: await worker(items[index], index),
            };
          } catch (reason) {
            results[index] = { status: "rejected", reason: String(reason) };
          }
        } else {
          results[index] = await worker(items[index], index);
        }
      }
    };
    await Promise.all(
      Array.from(
        { length: Math.min(concurrency, items.length) },
        () => lane(),
      ),
    );
    return results;
  };
  globalThis.mapLimit = (items, concurrency, worker) =>
    runLimited(items, concurrency, worker, false);
  globalThis.mapLimitSettled = (items, concurrency, worker) =>
    runLimited(items, concurrency, worker, true);
})();
`;

export class CodeModeRuntime {
  private readonly cells = new Map<string, Cell>();
  private readonly storedValues = new Map<string, string>();

  constructor(private readonly invoker: CanonicalCapabilityInvoker) {}

  async execute(
    code: string,
    context: ExecutionContext,
    yieldTimeMs = DEFAULT_YIELD_MS,
  ): Promise<CodeCellResult> {
    if (!code.trim()) throw new Error("exec requires non-empty JavaScript");

    const cellId = `cell_${randomUUID()}`;
    const controller = new AbortController();
    const signal = combineSignals(controller.signal, context.abortSignal);
    const promise = this.runCell(cellId, code, {
      ...context,
      abortSignal: signal,
    });
    this.cells.set(cellId, { controller, promise });

    return this.yieldCell(cellId, promise, yieldTimeMs);
  }

  async wait(
    cellId: string,
    options: { yieldTimeMs?: number; terminate?: boolean } = {},
  ): Promise<CodeCellResult> {
    const cell = this.cells.get(cellId);
    if (!cell) throw new Error(`Unknown or completed code cell: ${cellId}`);
    if (options.terminate) cell.controller.abort("Terminated by wait");
    return this.yieldCell(
      cellId,
      cell.promise,
      options.yieldTimeMs ?? DEFAULT_YIELD_MS,
    );
  }

  async dispose(): Promise<void> {
    const cells = [...this.cells.values()];
    for (const cell of cells)
      cell.controller.abort("Code-mode runtime disposed");
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      Promise.allSettled(cells.map((cell) => cell.promise)),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, DISPOSE_GRACE_MS);
      }),
    ]);
    if (timer) clearTimeout(timer);
    this.cells.clear();
  }

  private async yieldCell(
    cellId: string,
    promise: Promise<CodeCellResult>,
    requestedYieldMs: number,
  ): Promise<CodeCellResult> {
    const yieldTimeMs = Math.min(Math.max(0, requestedYieldMs), MAX_YIELD_MS);
    let timer: ReturnType<typeof setTimeout> | undefined;
    const running = new Promise<CodeCellResult>((resolve) => {
      timer = setTimeout(
        () => resolve({ cellId, status: "running", output: "" }),
        yieldTimeMs,
      );
    });
    const result = await Promise.race([promise, running]);
    if (timer) clearTimeout(timer);
    if (result.status !== "running") this.cells.delete(cellId);
    return result;
  }

  private async runCell(
    cellId: string,
    code: string,
    context: ExecutionContext,
  ): Promise<CodeCellResult> {
    const startedAt = Date.now();
    const output: string[] = [];
    const hostCalls = new Set<Promise<unknown>>();
    const deadline = Date.now() + MAX_CELL_RUNTIME_MS;
    let cpuDeadline = Date.now() + MAX_CPU_SLICE_MS;
    const QuickJS = await getQuickJS();
    const runtime = QuickJS.newRuntime();
    runtime.setMemoryLimit(MEMORY_LIMIT_BYTES);
    runtime.setInterruptHandler(
      () =>
        context.abortSignal?.aborted === true ||
        Date.now() > deadline ||
        Date.now() > cpuDeadline,
    );
    const vm = runtime.newContext();
    let pendingJobs = Promise.resolve();
    const pumpJobs = () => {
      pendingJobs = pendingJobs.then(() => {
        cpuDeadline = Date.now() + MAX_CPU_SLICE_MS;
        const result = runtime.executePendingJobs();
        if (result.error) {
          const error = vm.dump(result.error);
          result.error.dispose();
          throw new Error(serializeOutput(error));
        }
      });
      return pendingJobs;
    };

    const invokeHandle = vm.newFunction(
      "__apexInvoke",
      (nameHandle, inputHandle) => {
        const name = vm.getString(nameHandle);
        const input = JSON.parse(vm.getString(inputHandle)) as unknown;
        const deferred = vm.newPromise();
        const call = this.invoker.invoke(name, input, {
          parentToolCallId: context.parentToolCallId,
          messages: context.messages,
          abortSignal: context.abortSignal,
        });
        hostCalls.add(call);
        void call
          .then((result) => {
            const value = vm.newString(JSON.stringify(result ?? null));
            deferred.resolve(value);
            value.dispose();
          })
          .catch((error) => {
            const value = vm.newString(
              error instanceof Error ? error.message : String(error),
            );
            deferred.reject(value);
            value.dispose();
          })
          .finally(() => {
            hostCalls.delete(call);
            void pumpJobs();
          });
        return deferred.handle;
      },
    );
    vm.setProp(vm.global, "__apexInvoke", invokeHandle);
    invokeHandle.dispose();

    const textHandle = vm.newFunction("__apexText", (valueHandle) => {
      const value = JSON.parse(vm.getString(valueHandle)) as unknown;
      output.push(serializeOutput(value));
    });
    vm.setProp(vm.global, "__apexText", textHandle);
    textHandle.dispose();

    const storeHandle = vm.newFunction(
      "__apexStore",
      (keyHandle, valueHandle) => {
        this.storedValues.set(
          vm.getString(keyHandle),
          vm.getString(valueHandle),
        );
      },
    );
    vm.setProp(vm.global, "__apexStore", storeHandle);
    storeHandle.dispose();

    const loadHandle = vm.newFunction("__apexLoad", (keyHandle) => {
      const value = this.storedValues.get(vm.getString(keyHandle));
      return value === undefined ? vm.undefined : vm.newString(value);
    });
    vm.setProp(vm.global, "__apexLoad", loadHandle);
    loadHandle.dispose();

    try {
      cpuDeadline = Date.now() + MAX_CPU_SLICE_MS;
      vm.unwrapResult(
        vm.evalCode(GUEST_PRELUDE, "apex-code-mode.js"),
      ).dispose();
      cpuDeadline = Date.now() + MAX_CPU_SLICE_MS;
      const evaluated = vm.evalCode(
        `(async () => {\n${code}\n})()`,
        "apex-exec.js",
      );
      const promiseHandle = vm.unwrapResult(evaluated);
      const resolution = vm.resolvePromise(promiseHandle);
      // Register the host resolver before pumping. QuickJS promises advance
      // only while pending jobs are executed, including immediately-resolved
      // async functions that never call a host capability.
      await pumpJobs();
      const resolved = await resolution;
      promiseHandle.dispose();
      const resultHandle = vm.unwrapResult(resolved);
      const returned = vm.dump(resultHandle);
      resultHandle.dispose();
      await Promise.allSettled([...hostCalls]);
      await pumpJobs();
      if (returned !== undefined) output.push(serializeOutput(returned));
      const observation = this.invoker.completeCell(context.parentToolCallId);
      return {
        cellId,
        status: "completed",
        output: truncateOutput(output.filter(Boolean).join("\n")),
        metrics: {
          ...observation.metrics,
          durationMs: Date.now() - startedAt,
        },
        ...(observation.guidance.length > 0
          ? { guidance: observation.guidance }
          : {}),
      };
    } catch (error) {
      const terminated = context.abortSignal?.aborted === true;
      const observation = this.invoker.completeCell(context.parentToolCallId);
      return {
        cellId,
        status: terminated ? "terminated" : "failed",
        output: truncateOutput(
          error instanceof Error ? error.message : String(error),
        ),
        metrics: {
          ...observation.metrics,
          durationMs: Date.now() - startedAt,
        },
        ...(observation.guidance.length > 0
          ? { guidance: observation.guidance }
          : {}),
      };
    } finally {
      vm.dispose();
      runtime.dispose();
    }
  }
}
