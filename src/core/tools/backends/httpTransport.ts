import { randomBytes } from "node:crypto";
import type {
  BodyCaptureStopReason,
  HttpRequestResult,
} from "../../agents/offSecAgent/tools/httpRequest";
import { resolverSessionFromCtx } from "../../agents/offSecAgent/tools/scopeGuard";
import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { buildWindowsCurlCommand } from "../../agents/offSecAgent/tools/windowsCurl";
import { resolveEffectiveHeaders, shellQuote } from "../../http/targetHeaders";

const MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024;

type CappedBodyRead = {
  text: string;
  received: number;
  stopReason: "end" | "byte-cap" | "aborted" | "error";
  cause?: unknown;
};

export async function readHttpBodyCapped(
  response: Response,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<CappedBodyRead> {
  const captured = (): CappedBodyRead => ({
    text: new TextDecoder().decode(buf.subarray(0, received)),
    received,
    stopReason,
    cause,
  });
  // Assigned by the loop below; the closures above read them after it exits.
  let buf = new Uint8Array(0);
  let received = 0;
  let stopReason: CappedBodyRead["stopReason"] = "end";
  let cause: unknown;

  if (signal?.aborted) {
    response.body?.cancel().catch(() => {});
    stopReason = "aborted";
    return captured();
  }
  const body = response.body;
  if (!body) return { text: "", received: 0, stopReason: "end" };

  const reader = body.getReader();
  // Native-stream arbiter: ONE race, created before the first read. The abort
  // listener resolves the sentinel BEFORE cancelling, and reader.closed
  // stays raw inside the race — a reaction hop would reorder same-turn
  // events. Whichever settles first is the terminal outcome.
  let onAbort: (() => void) | undefined;
  const aborted = signal
    ? new Promise<"aborted">((resolve) => {
        onAbort = () => {
          resolve("aborted");
          reader.cancel().catch(() => {});
        };
        signal.addEventListener("abort", onAbort, { once: true });
      })
    : null;
  const ended = (
    aborted ? Promise.race([reader.closed, aborted]) : reader.closed
  ).then<
    { kind: "end" } | { kind: "aborted" },
    { kind: "error"; cause: unknown }
  >(
    (result) => ({ kind: result === "aborted" ? "aborted" : "end" }),
    (error) => ({ kind: "error", cause: error }),
  );

  buf = new Uint8Array(Math.min(maxBytes, 64 * 1024));

  const append = (value: Uint8Array, take: number) => {
    if (take <= 0) return;
    if (received + take > buf.byteLength) {
      // Geometric growth, hard-capped at maxBytes.
      let size = buf.byteLength;
      while (size < received + take && size < maxBytes) size *= 2;
      const next = new Uint8Array(Math.min(size, maxBytes));
      next.set(buf.subarray(0, received));
      buf = next;
    }
    buf.set(value.subarray(0, take), received);
    received += take;
  };

  try {
    while (true) {
      let result: Awaited<ReturnType<typeof reader.read>>;
      try {
        result = await reader.read();
      } catch {
        // The arbiter carries the terminal cause; the read's rejection is
        // the same event seen from the read side. Processing failures below
        // propagate through the finally — they are not stream outcomes.
        break;
      }
      const { done, value } = result;
      if (done) break;
      if (!value?.byteLength) continue;
      const room = maxBytes - received;
      if (value.byteLength > room) {
        append(value, room);
        stopReason = "byte-cap";
        reader.cancel().catch(() => {});
        break;
      }
      append(value, value.byteLength);
      // At the exact cap, keep reading until EOF or a nonempty overflow chunk.
    }
  } finally {
    if (onAbort) signal?.removeEventListener("abort", onAbort);
    // Cancel before release: a processing exception escaping the loop must
    // not leave the stream merely released while the producer keeps pulling.
    reader.cancel().catch(() => {});
    try {
      reader.releaseLock();
    } catch {
      // cancel()/read failure may have already released the lock
    }
  }

  // Cap is explicit and final — never awaited or overwritten by the arbiter.
  if (stopReason === "byte-cap") return captured();

  const end = await ended;
  if (end.kind === "aborted") {
    stopReason = "aborted";
  } else if (end.kind === "error") {
    // Identity, not name: native fetch cancellation rejects the body with
    // the signal's own reason object; an unrelated AbortError-shaped error
    // from an adapter stays an error even once the host signal aborts.
    cause = end.cause;
    stopReason =
      signal?.aborted && end.cause === signal.reason ? "aborted" : "error";
  }
  return captured();
}

export async function requestSandboxHttp(
  ctx: ToolContext,
  opts: {
    url: string;
    method: string;
    headers?: Record<string, string>;
    body?: string;
    followRedirects: boolean;
    timeout: number | undefined;
  },
): Promise<HttpRequestResult> {
  const { url, method, headers, body, followRedirects, timeout } = opts;

  const { sandbox } = ctx;
  if (!sandbox) {
    throw new Error("executeSandboxHttpRequest requires a sandbox");
  }

  if (ctx.abortSignal?.aborted) {
    return {
      success: false,
      status: 0,
      statusText: "",
      headers: {},
      body: "",
      url,
      method,
      redirected: false,
      error: "Request aborted by user",
      capture: {
        complete: false,
        stopReason: "aborted",
        capturedBytes: 0,
        capturedBytesBasis: "raw",
      },
    };
  }

  // Hoisted so the `finally` can delete the request-body temp file on every
  // path — otherwise every POST/PUT/PATCH leaves a `/tmp/apex_http_body_*`
  // file behind for the life of the sandbox, and a body-heavy scan can fill
  // the disk (ENOSPC).
  let bodyTempFile: string | null = null;

  try {
    // Resolve session/credential headers so the sandbox curl path matches
    // the local fetch path. Caller `headers` win as the request layer.
    const mergedHeaders = resolveEffectiveHeaders(
      resolverSessionFromCtx(ctx),
      url,
      headers,
    );

    const timeoutSeconds =
      timeout === undefined ? 0 : Math.ceil(timeout / 1000);
    const nonce = randomBytes(8).toString("hex");
    const exitMarker = `__APEX_${nonce}_CURL_EXIT_`;
    // Windows: +15s headroom — 5s PowerShell startup, 5s EOF/drain process-exit
    // grace, 5s kill confirmation — before the adapter tears the call down.
    // Linux keeps the existing floor.
    const executeOpts: {
      timeout?: number;
      envVars?: Record<string, string>;
    } = {
      timeout:
        timeout === undefined
          ? undefined
          : sandbox.type === "windows"
            ? Math.max(timeoutSeconds + 15, 30)
            : Math.max(timeoutSeconds, 30),
    };

    let command: string;
    if (sandbox.type === "windows") {
      // Windows helper: fixed encoded script; request data (CRT-quoted argv,
      // base64 body, marker, byte cap) travels in envVars. No POSIX printf
      // /tmp body staging and no rm cleanup on this path.
      const win = buildWindowsCurlCommand({
        url,
        method,
        headers: mergedHeaders,
        body:
          body && ["POST", "PUT", "PATCH"].includes(method) ? body : undefined,
        followRedirects,
        timeoutSeconds,
        maxBytes: MAX_DOWNLOAD_BYTES,
        exitMarker,
      });
      command = win.command;
      executeOpts.envVars = win.envVars;
    } else {
      let curlCommand = `curl -sS -i -X ${method}`;
      for (const [key, value] of Object.entries(mergedHeaders)) {
        curlCommand += ` -H "${shellQuote(`${key}: ${value}`)}"`;
      }

      // If we have a body to send, write it to a temp file in the sandbox
      // to avoid shell escaping issues with multiline content
      if (body && ["POST", "PUT", "PATCH"].includes(method)) {
        bodyTempFile = `/tmp/apex_http_body_${Date.now()}_${Math.random().toString(36).slice(2, 11)}.txt`;

        // Use printf to safely write the body to the temp file
        const escapedForPrintf = body
          .replace(/\\/g, "\\\\")
          .replace(/%/g, "%%");
        const writeCommand = `printf '%s' '${escapedForPrintf.replace(/'/g, "'\\''")}' > ${bodyTempFile}`;

        const writeResult = await sandbox.execute(writeCommand, {
          timeout: 30,
        });
        if (!writeResult.success || writeResult.exitCode !== 0) {
          return {
            success: false,
            error: `Failed to write request body to sandbox temp file: ${writeResult.stderr || writeResult.stdout}`,
            url,
            method,
            status: 0,
            statusText: "",
            headers: {},
            body: "",
            redirected: false,
            capture: {
              complete: false,
              stopReason: "error",
              capturedBytes: 0,
              capturedBytesBasis: "raw",
            },
          };
        }

        curlCommand += ` --data-binary @${bodyTempFile}`;
      }

      if (followRedirects) {
        curlCommand += " -L";
      }

      curlCommand += ` --max-time ${timeoutSeconds}`;
      curlCommand += ` "${url}"`;

      // Reserve metadata space so a completed exact-cap response keeps its
      // exit marker. Any response bytes using that reserve are clipped below.
      // Base64 preserves raw bytes through the adapter's text-only stdout.
      const markerBytes = Buffer.byteLength(`\n${exitMarker}255\n`);
      command = `( ${curlCommand}; printf '\\n${exitMarker}%s\\n' "$?" ) 2>&1 | head -c ${MAX_DOWNLOAD_BYTES + markerBytes} | base64`;
    }

    const result = await sandbox.execute(command, executeOpts);

    const rawOutput =
      sandbox.type === "windows"
        ? undefined
        : Buffer.from(result.stdout || "", "base64");
    const output = rawOutput?.toString("utf8") ?? result.stdout ?? "";
    // Marker absent = head cut the stream at the cap (curl SIGPIPE'd before
    // writing it) or the pipeline was killed — either way incomplete. The
    // random nonce keeps a hostile body from forging a clean exit. Windows
    // native termination can be negative, so the exit is parsed signed.
    const markerMatch = output.match(
      new RegExp(`\\n?${exitMarker}(-?\\d+)\\n?$`),
    );
    const curlExit = markerMatch ? parseInt(markerMatch[1], 10) : null;
    const unmarkedOutput =
      markerMatch !== null ? output.slice(0, markerMatch.index) : output;
    const responseBytes = rawOutput
      ? rawOutput.length - (markerMatch ? Buffer.byteLength(markerMatch[0]) : 0)
      : 0;
    const captureOverflow =
      rawOutput !== undefined && responseBytes > MAX_DOWNLOAD_BYTES;
    const boundedOutput = rawOutput
      ? rawOutput
          .subarray(0, Math.min(responseBytes, MAX_DOWNLOAD_BYTES))
          .toString("utf8")
      : unmarkedOutput;

    // Headers tolerate spec CRLF; the body is sliced raw from the original
    // output — splitting the whole stream would normalize its line endings
    // and corrupt evidence.
    let statusLine = "";
    const responseHeaders: Record<string, string> = {};
    let bodyStart = -1;
    let headerStart = 0;

    const statusLineMatch = boundedOutput.match(/(?:^|\r?\n)(HTTP\/[^\r\n]*)/);
    if (statusLineMatch?.index !== undefined) {
      statusLine = statusLineMatch[1];
      headerStart = statusLineMatch.index + statusLineMatch[0].length;
      const sepMatch = boundedOutput.slice(headerStart).match(/\r?\n\r?\n/);
      if (sepMatch?.index !== undefined) {
        const headerBlock = boundedOutput.slice(
          headerStart,
          headerStart + sepMatch.index,
        );
        for (const line of headerBlock.split(/\r?\n/)) {
          if (line.trim() === "") continue;
          const headerMatch = line.match(/^([^:]+):\s*(.+)$/);
          if (headerMatch) {
            responseHeaders[headerMatch[1].toLowerCase()] = headerMatch[2];
          }
        }
        bodyStart = headerStart + sepMatch.index + sepMatch[0].length;
      }
    }

    const statusMatch = statusLine.match(
      /^HTTP\/[\d.]+[ \t]+(\d{3})(?:[ \t]+(.*))?$/,
    );
    const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
    const statusText = statusMatch ? (statusMatch[2]?.trim() ?? "") : "Unknown";
    // No HTTP line at all → the transport noise/error text is the body
    // evidence; a status line without a blank separator keeps the raw
    // remainder after it.
    const responseBody =
      bodyStart >= 0
        ? boundedOutput.slice(bodyStart)
        : boundedOutput.slice(headerStart);

    // Transport outcome comes from curl's exit, not the parsed status line —
    // a --max-time cutoff (exit 28) still writes "HTTP/1.1 200" plus a
    // partial body. Partial status/headers/body are returned as evidence.
    const sandboxTransportOk = result.success && result.exitCode === 0;
    const transferComplete =
      sandboxTransportOk && curlExit === 0 && !captureOverflow;
    const stopReason: BodyCaptureStopReason = !sandboxTransportOk
      ? "sandbox-exec"
      : captureOverflow || curlExit == null
        ? "byte-cap"
        : curlExit !== 0
          ? "curl-exit"
          : "end";
    const capturedBytes = Buffer.byteLength(responseBody, "utf-8");
    const declaredRaw = responseHeaders["content-length"];
    const declared = declaredRaw ? Number.parseInt(declaredRaw, 10) : NaN;
    const declaredBytes =
      Number.isSafeInteger(declared) && declared >= 0 ? declared : undefined;
    // Native curl/helper errors surface via sandbox stderr — include them in
    // the failure diagnostics instead of suppressing them.
    const redactedSandboxStderr = result.stderr || "";
    const incompleteNote = !sandboxTransportOk
      ? `sandbox execution failed (exit ${result.exitCode})${redactedSandboxStderr ? `: ${redactedSandboxStderr}` : ""}; output may be partial`
      : captureOverflow || curlExit == null
        ? `output capped at ${MAX_DOWNLOAD_BYTES} bytes; ${curlExit == null ? "curl exit unknown" : `curl exited ${curlExit}`} — for larger evidence, save it inside your sandbox file workspace with execute_command (curl -o file), then inspect read_file byte windows`
        : curlExit !== 0
          ? `curl exited ${curlExit}${redactedSandboxStderr ? `: ${redactedSandboxStderr}` : ""}; output may be partial`
          : undefined;

    return {
      success: transferComplete && status >= 200 && status < 400,
      error: incompleteNote,
      status,
      statusText,
      headers: responseHeaders,
      body: responseBody,
      url,
      redirected: false,
      capture: {
        complete: transferComplete,
        stopReason,
        capturedBytes,
        capturedBytesBasis: "decoded",
        ...(declaredBytes !== undefined ? { declaredBytes } : {}),
      },
    };
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: msg,
      status: 0,
      statusText: "Error",
      headers: {},
      body: "",
      url,
      redirected: false,
      capture: {
        complete: false,
        stopReason: "error",
        capturedBytes: 0,
        capturedBytesBasis: "raw",
      },
    };
  } finally {
    // Reclaim the request-body temp file now that curl has read it. Best-effort
    // — a failed cleanup must not change the request result.
    if (bodyTempFile) {
      await sandbox
        .execute(`rm -f ${bodyTempFile}`, { timeout: 10 })
        .catch(() => {});
    }
  }
}
