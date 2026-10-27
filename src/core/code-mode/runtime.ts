import { randomUUID } from "node:crypto";
import RELEASE_SYNC from "@jitl/quickjs-singlefile-cjs-release-sync";
import type { ModelMessage } from "ai";
import { newQuickJSWASMModule, Scope } from "quickjs-emscripten";
import type {
  CanonicalCapabilityInvoker,
  CodeModeCellMetrics,
  CodeModeEvidenceReference,
} from "./capabilityInvoker";

const DEFAULT_YIELD_MS = 10_000;
const MAX_YIELD_MS = 60_000;
const MAX_CELL_RUNTIME_MS = 30 * 60 * 1000;
const MAX_CPU_SLICE_MS = 2_000;
const DISPOSE_GRACE_MS = 5_000;
const MEMORY_LIMIT_BYTES = 64 * 1024 * 1024;
const MAX_OUTPUT_CHARS = 30_000;
const MAX_STORED_VALUE_CHARS = 1_000_000;
const MAX_NESTED_RESULT_CHARS = 1_000_000;
const MAX_STORED_TOTAL_CHARS = 8_000_000;
const MAX_NESTED_CALLS = 1_000;

// Embed WASM so Bun bundles and standalone binaries need no adjacent asset.
let quickJS: ReturnType<typeof newQuickJSWASMModule> | undefined;

export type CodeCellStatus = "completed" | "failed" | "running" | "terminated";

export type CodeCellResult = {
  cellId: string;
  status: CodeCellStatus;
  output: string;
  metrics?: CodeModeCellMetrics & { durationMs: number };
  evidence?: CodeModeEvidenceReference[];
  guidance?: string[];
};

type ExecutionContext = {
  parentToolCallId: string;
  messages: ModelMessage[];
  abortSignal?: AbortSignal;
  experimental_context?: unknown;
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
  const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const bytesToBase64 = (bytes) => {
    let output = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const a = bytes[i];
      const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
      const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
      output += BASE64[a >> 2];
      output += BASE64[((a & 3) << 4) | (b >> 4)];
      output += i + 1 < bytes.length ? BASE64[((b & 15) << 2) | (c >> 6)] : "=";
      output += i + 2 < bytes.length ? BASE64[c & 63] : "=";
    }
    return output;
  };
  const base64ToBytes = (value) => {
    const clean = String(value).replace(/\\s+/g, "").replace(/=+$/, "");
    const bytes = [];
    let bits = 0;
    let bitCount = 0;
    for (const char of clean) {
      const index = BASE64.indexOf(char);
      if (index < 0) throw new TypeError("Invalid base64 input");
      bits = (bits << 6) | index;
      bitCount += 6;
      if (bitCount >= 8) {
        bitCount -= 8;
        bytes.push((bits >> bitCount) & 255);
      }
    }
    return bytes;
  };
  const utf8ToBytes = (value) => {
    const encoded = unescape(encodeURIComponent(String(value)));
    return Array.from(encoded, (char) => char.charCodeAt(0));
  };
  const bytesToUtf8 = (bytes) => {
    const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
    return decodeURIComponent(escape(binary));
  };
  class ApexBuffer extends Uint8Array {
    static from(value, encoding = "utf8") {
      if (value instanceof Uint8Array || Array.isArray(value)) return new ApexBuffer(value);
      const normalized = String(encoding).toLowerCase();
      if (normalized === "base64") return new ApexBuffer(base64ToBytes(value));
      if (normalized === "hex") {
        const input = String(value);
        if (!/^(?:[0-9a-f]{2})*$/i.test(input)) throw new TypeError("Invalid hex input");
        return new ApexBuffer(input.match(/../g)?.map((part) => parseInt(part, 16)) || []);
      }
      return new ApexBuffer(utf8ToBytes(value));
    }
    toString(encoding = "utf8") {
      const normalized = String(encoding).toLowerCase();
      if (normalized === "base64") return bytesToBase64(this);
      if (normalized === "hex") return Array.from(this, (byte) => byte.toString(16).padStart(2, "0")).join("");
      return bytesToUtf8(this);
    }
  }
  const sleep = (ms) => __apexSleep(ms);
  globalThis.Buffer = ApexBuffer;
  globalThis.btoa = (value) => bytesToBase64(Array.from(String(value), (char) => char.charCodeAt(0) & 255));
  globalThis.atob = (value) => Array.from(base64ToBytes(value), (byte) => String.fromCharCode(byte)).join("");
  globalThis.sleep = sleep;
  globalThis.setTimeout = (callback, ms, ...args) => sleep(ms).then(() => callback(...args));
  globalThis.require = (name) => {
    if (name === "buffer") return { Buffer: ApexBuffer };
    if (name === "timers/promises") return { setTimeout: sleep };
    throw new Error("require(" + JSON.stringify(name) + ") is unavailable in the isolated runtime; use JavaScript globals for computation and tools.call with an allowed capability for host operations");
  };
  const laneFor = (name) => {
    if (name === "execute_command") return "shell";
    if (name.startsWith("browser_")) return "browser";
    return undefined;
  };
  const activeLanes = new Set();
  const invoke = async (name, input = {}) => {
    const lane = laneFor(name);
    if (lane && activeLanes.has(lane)) {
      const hint = lane === "shell"
        ? "execute_command is single-lane. Await each command before starting the next; use JavaScript in exec to compose other independent capabilities."
        : "Browser operations are single-lane and stateful; await each mutation before starting the next.";
      const error = new Error(hint);
      error.toJSON = () => ({ name: "Error", message: hint });
      throw error;
    }
    if (lane) activeLanes.add(lane);
    try {
      const normalizedInput = name === "execute_command" && input && typeof input === "object" && !Array.isArray(input) && input.timeout == null && input.timeoutSeconds == null
        ? { ...input, timeout: 120 }
        : input;
      const encoded = await __apexInvoke(name, JSON.stringify(normalizedInput));
      return JSON.parse(encoded);
    } finally {
      if (lane) activeLanes.delete(lane);
    }
  };
  const describe = async (name) => JSON.parse(await __apexDescribe(String(name)));
  const browser = Object.freeze({
    navigate: (input) => invoke("browser_navigate", input),
    snapshot: (input) => invoke("browser_snapshot", input),
    click: (input) => invoke("browser_click", input),
    fill: (input) => invoke("browser_fill", input),
    evaluate: (input) => invoke("browser_evaluate", input),
    console: (input) => invoke("browser_console", input),
    getCookies: (input) => invoke("browser_get_cookies", input),
  });
  globalThis.tools = Object.freeze({
    call: invoke,
    describe,
    browser,
  });
  globalThis.ALL_TOOLS = Object.freeze(__APEX_ALL_TOOLS__);
  globalThis.text = (value) => __apexText(JSON.stringify(value) ?? "null");
  globalThis.store = (key, value) => {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("Stored values must be JSON serializable");
    if (encoded.length > 1000000) {
      throw new Error("Stored code-mode values are limited to 1000000 characters; persist large artifacts with create_file instead");
    }
    return __apexStore(key, encoded);
  };
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
    let stopped = false;
    const lane = async () => {
      while (!stopped && nextIndex < items.length) {
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
          try {
            results[index] = await worker(items[index], index);
          } catch (error) {
            stopped = true;
            throw error;
          }
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
  private storedChars = 0;
  private disposePromise?: Promise<void>;
  private disposed = false;

  private readonly guestPrelude: string;

  constructor(
    private readonly invoker: CanonicalCapabilityInvoker,
    availableTools: Iterable<string> = [],
    private readonly onCellComplete?: (result: CodeCellResult) => void,
  ) {
    this.guestPrelude = GUEST_PRELUDE.replace(
      "__APEX_ALL_TOOLS__",
      JSON.stringify([...availableTools]),
    );
  }

  async execute(
    code: string,
    context: ExecutionContext,
    yieldTimeMs = DEFAULT_YIELD_MS,
  ): Promise<CodeCellResult> {
    if (this.disposed) throw new Error("Code-mode runtime is disposed");
    if (!code.trim()) throw new Error("exec requires non-empty JavaScript");

    const cellId = `cell_${randomUUID()}`;
    const controller = new AbortController();
    const signal = combineSignals(controller.signal, context.abortSignal);
    const timer = setTimeout(
      () => controller.abort("Code-mode execution deadline exceeded"),
      MAX_CELL_RUNTIME_MS,
    );
    const promise = this.runCell(cellId, code, {
      ...context,
      abortSignal: signal,
    }).finally(() => clearTimeout(timer));
    this.cells.set(cellId, { controller, promise });

    return this.yieldCell(cellId, promise, yieldTimeMs);
  }

  async wait(
    cellId: string,
    options: {
      yieldTimeMs?: number;
      terminate?: boolean;
      abortSignal?: AbortSignal;
    } = {},
  ): Promise<CodeCellResult> {
    options.abortSignal?.throwIfAborted();
    const cell = this.cells.get(cellId);
    if (!cell) throw new Error(`Unknown or completed code cell: ${cellId}`);
    if (options.terminate) cell.controller.abort("Terminated by wait");
    return this.yieldCell(
      cellId,
      cell.promise,
      options.terminate ? null : (options.yieldTimeMs ?? DEFAULT_YIELD_MS),
      options.abortSignal,
    );
  }

  async dispose(): Promise<void> {
    this.disposePromise ??= this.disposeCells();
    return this.disposePromise;
  }

  private async disposeCells(): Promise<void> {
    this.disposed = true;
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
    this.storedValues.clear();
    this.storedChars = 0;
  }

  private async yieldCell(
    cellId: string,
    promise: Promise<CodeCellResult>,
    requestedYieldMs: number | null,
    abortSignal?: AbortSignal,
  ): Promise<CodeCellResult> {
    abortSignal?.throwIfAborted();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const running = new Promise<CodeCellResult>((resolve) => {
      if (requestedYieldMs === null) return;
      const yieldTimeMs = Math.min(Math.max(0, requestedYieldMs), MAX_YIELD_MS);
      timer = setTimeout(
        () => resolve({ cellId, status: "running", output: "" }),
        yieldTimeMs,
      );
    });
    let onAbort: (() => void) | undefined;
    const cancelled = new Promise<never>((_, reject) => {
      if (!abortSignal) return;
      onAbort = () => reject(abortSignal.reason);
      abortSignal.addEventListener("abort", onAbort, { once: true });
    });
    try {
      const result = await Promise.race([promise, running, cancelled]);
      if (result.status !== "running") this.cells.delete(cellId);
      return result;
    } finally {
      if (timer) clearTimeout(timer);
      if (onAbort) abortSignal?.removeEventListener("abort", onAbort);
    }
  }

  private async runCell(
    cellId: string,
    code: string,
    context: ExecutionContext,
  ): Promise<CodeCellResult> {
    const startedAt = Date.now();
    let output = "";
    const appendOutput = (value: unknown) => {
      if (output.length > MAX_OUTPUT_CHARS) return;
      const serialized = serializeOutput(value);
      if (serialized)
        output = truncateOutput(
          output ? `${output}\n${serialized}` : serialized,
        );
    };
    const hostCalls = new Set<Promise<void>>();
    let nestedResultChars = 0;
    let nestedCalls = 0;
    let loadedValueChars = 0;
    const deadline = Date.now() + MAX_CELL_RUNTIME_MS;
    let cpuDeadline = Date.now() + MAX_CPU_SLICE_MS;
    const scope = new Scope();
    let onAbort: (() => void) | undefined;
    let drainHostCalls = async () => {};
    try {
      quickJS ??= newQuickJSWASMModule(RELEASE_SYNC).catch((error) => {
        quickJS = undefined;
        throw error;
      });
      const QuickJS = await quickJS;
      context.abortSignal?.throwIfAborted();
      const runtime = scope.manage(QuickJS.newRuntime());
      runtime.setMemoryLimit(MEMORY_LIMIT_BYTES);
      runtime.setInterruptHandler(
        () =>
          context.abortSignal?.aborted === true ||
          Date.now() > deadline ||
          Date.now() > cpuDeadline,
      );
      const vm = scope.manage(runtime.newContext());
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

      const bridgePromise = <T>(
        deferred: ReturnType<typeof vm.newPromise>,
        operation: Promise<T>,
        serialize: (value: T) => string | undefined,
        onAbort?: () => void,
      ) => {
        let settled = false;
        const operationState: {
          finish?: (kind: "resolve" | "reject", value?: unknown) => void;
        } = {};
        let completeBridge: () => void = () => {};
        const bridge = new Promise<void>((resolve) => {
          completeBridge = resolve;
        });
        hostCalls.add(bridge);

        const finish = (kind: "resolve" | "reject", value?: unknown) => {
          if (settled) return;
          settled = true;
          operationState.finish = undefined;
          context.abortSignal?.removeEventListener("abort", abort);

          const encoded =
            kind === "resolve"
              ? serialize(value as T)
              : value instanceof Error
                ? value.message
                : String(value);
          const handle =
            encoded === undefined ? vm.undefined : vm.newString(encoded);
          if (kind === "resolve") deferred.resolve(handle);
          else deferred.reject(handle);
          if (handle !== vm.undefined) handle.dispose();

          void pumpJobs()
            .catch(() => undefined)
            .finally(() => {
              hostCalls.delete(bridge);
              completeBridge();
            });
        };
        operationState.finish = finish;
        const abort = () => {
          onAbort?.();
          finish(
            "reject",
            context.abortSignal?.reason ?? "Code-mode execution aborted",
          );
        };

        if (context.abortSignal?.aborted) abort();
        else
          context.abortSignal?.addEventListener("abort", abort, { once: true });

        void operation.then(
          (value) => operationState.finish?.("resolve", value),
          (error) => operationState.finish?.("reject", error),
        );
        return deferred.handle;
      };
      drainHostCalls = async () => {
        while (hostCalls.size > 0) {
          await Promise.allSettled([...hostCalls]);
          await pendingJobs.catch(() => undefined);
        }
        await pendingJobs.catch(() => undefined);
      };

      const invokeHandle = scope.manage(
        vm.newFunction("__apexInvoke", (nameHandle, inputHandle) => {
          if (++nestedCalls > MAX_NESTED_CALLS) {
            throw new Error(
              `Code-mode cells are limited to ${MAX_NESTED_CALLS} nested calls`,
            );
          }
          const name = vm.getString(nameHandle);
          const input = JSON.parse(vm.getString(inputHandle)) as unknown;
          const deferred = vm.newPromise();
          const call = this.invoker
            .invoke(name, input, {
              parentToolCallId: context.parentToolCallId,
              messages: context.messages,
              abortSignal: context.abortSignal,
              experimental_context: context.experimental_context,
            })
            .then((result) => {
              const encoded = JSON.stringify(result ?? null);
              if (
                nestedResultChars + encoded.length >
                MAX_NESTED_RESULT_CHARS
              ) {
                throw new Error(
                  `Code-mode nested results are limited to ${MAX_NESTED_RESULT_CHARS} characters per cell; split large reads across cells and persist only compact state or artifacts with create_file`,
                );
              }
              nestedResultChars += encoded.length;
              return encoded;
            });
          return bridgePromise(deferred, call, (result) => result);
        }),
      );
      vm.setProp(vm.global, "__apexInvoke", invokeHandle);
      invokeHandle.dispose();

      const describeHandle = scope.manage(
        vm.newFunction("__apexDescribe", (nameHandle) => {
          const deferred = vm.newPromise();
          return bridgePromise(
            deferred,
            this.invoker.describe(vm.getString(nameHandle)),
            (result) => JSON.stringify(result),
          );
        }),
      );
      vm.setProp(vm.global, "__apexDescribe", describeHandle);
      describeHandle.dispose();

      const sleepHandle = scope.manage(
        vm.newFunction("__apexSleep", (durationHandle) => {
          const durationMs = Math.min(
            30_000,
            Math.max(0, Math.floor(vm.getNumber(durationHandle))),
          );
          const deferred = vm.newPromise();
          let timer: ReturnType<typeof setTimeout> | undefined;
          let finishSleep: () => void = () => {};
          const sleep = new Promise<void>((resolve) => {
            finishSleep = resolve;
            timer = setTimeout(resolve, durationMs);
          });
          return bridgePromise(
            deferred,
            sleep,
            () => undefined,
            () => {
              if (timer) clearTimeout(timer);
              finishSleep();
            },
          );
        }),
      );
      vm.setProp(vm.global, "__apexSleep", sleepHandle);
      sleepHandle.dispose();

      const textHandle = scope.manage(
        vm.newFunction("__apexText", (valueHandle) => {
          const value = JSON.parse(vm.getString(valueHandle)) as unknown;
          appendOutput(value);
        }),
      );
      vm.setProp(vm.global, "__apexText", textHandle);
      textHandle.dispose();

      const storeHandle = scope.manage(
        vm.newFunction("__apexStore", (keyHandle, valueHandle) => {
          const value = vm.getString(valueHandle);
          if (value.length > MAX_STORED_VALUE_CHARS) {
            throw new Error(
              `Stored code-mode values are limited to ${MAX_STORED_VALUE_CHARS} characters; persist large artifacts with create_file instead`,
            );
          }
          const key = vm.getString(keyHandle);
          const previous = this.storedValues.get(key);
          const total =
            this.storedChars -
            (previous?.length ?? 0) +
            value.length +
            (previous === undefined ? key.length : 0);
          if (total > MAX_STORED_TOTAL_CHARS) {
            throw new Error(
              `Stored code-mode state is limited to ${MAX_STORED_TOTAL_CHARS} characters in total; persist large artifacts with create_file instead`,
            );
          }
          this.storedValues.set(key, value);
          this.storedChars = total;
        }),
      );
      vm.setProp(vm.global, "__apexStore", storeHandle);
      storeHandle.dispose();

      const loadHandle = scope.manage(
        vm.newFunction("__apexLoad", (keyHandle) => {
          const value = this.storedValues.get(vm.getString(keyHandle));
          if (value === undefined) return vm.undefined;
          if (loadedValueChars + value.length > MAX_STORED_VALUE_CHARS) {
            throw new Error(
              `Loaded code-mode values are limited to ${MAX_STORED_VALUE_CHARS} characters per cell; load compact state and page large artifacts with read_file`,
            );
          }
          loadedValueChars += value.length;
          return vm.newString(value);
        }),
      );
      vm.setProp(vm.global, "__apexLoad", loadHandle);
      loadHandle.dispose();

      cpuDeadline = Date.now() + MAX_CPU_SLICE_MS;
      vm.unwrapResult(
        vm.evalCode(this.guestPrelude, "apex-code-mode.js"),
      ).dispose();
      cpuDeadline = Date.now() + MAX_CPU_SLICE_MS;
      const evaluated = vm.evalCode(
        `(async () => {\n${code}\n})()`,
        "apex-exec.js",
      );
      const promiseHandle = scope.manage(vm.unwrapResult(evaluated));
      const resolution = vm.resolvePromise(promiseHandle);
      // Register the resolver first; even pure guest promises need a job pump.
      await pumpJobs();
      // Interrupts cannot wake an idle guest promise, so also cancel the host wait.
      const cancelled = new Promise<never>((_, reject) => {
        onAbort = () =>
          reject(
            new Error(
              String(
                context.abortSignal?.reason ?? "Code-mode execution aborted",
              ),
            ),
          );
        if (context.abortSignal?.aborted) onAbort();
        else
          context.abortSignal?.addEventListener("abort", onAbort, {
            once: true,
          });
      });
      const resolved = await Promise.race([resolution, cancelled]);
      const resultHandle = vm.unwrapResult(resolved);
      const returned = vm.dump(resultHandle);
      resultHandle.dispose();
      await drainHostCalls();
      await pumpJobs();
      if (returned !== undefined) appendOutput(returned);
      const observation = this.invoker.completeCell(context.parentToolCallId);
      const result: CodeCellResult = {
        cellId,
        status: "completed",
        output,
        metrics: {
          ...observation.metrics,
          durationMs: Date.now() - startedAt,
        },
        ...(observation.evidence.length > 0
          ? { evidence: observation.evidence }
          : {}),
        ...(observation.guidance.length > 0
          ? { guidance: observation.guidance }
          : {}),
      };
      this.notifyCellComplete(result);
      return result;
    } catch (error) {
      // Drain sibling calls after rejection so no callback touches a freed VM.
      await drainHostCalls();
      const terminated = context.abortSignal?.aborted === true;
      const observation = this.invoker.completeCell(context.parentToolCallId);
      const result: CodeCellResult = {
        cellId,
        status: terminated ? "terminated" : "failed",
        output: truncateOutput(
          error instanceof Error ? error.message : String(error),
        ),
        metrics: {
          ...observation.metrics,
          durationMs: Date.now() - startedAt,
        },
        ...(observation.evidence.length > 0
          ? { evidence: observation.evidence }
          : {}),
        ...(observation.guidance.length > 0
          ? { guidance: observation.guidance }
          : {}),
      };
      this.notifyCellComplete(result);
      return result;
    } finally {
      if (onAbort) context.abortSignal?.removeEventListener("abort", onAbort);
      scope.dispose();
    }
  }

  private notifyCellComplete(result: CodeCellResult): void {
    try {
      this.onCellComplete?.(result);
    } catch {
      // Metrics callbacks must not change the execution result or VM teardown.
    }
  }
}
