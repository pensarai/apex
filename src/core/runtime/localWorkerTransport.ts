import { chmod, unlink } from "node:fs/promises";
import http from "node:http";
import { createConnection, type Socket } from "node:net";
import {
  type LocalWorkerRequest,
  parseWorkerRequest,
  parseWorkerSnapshot,
  type WorkerSnapshot,
} from "./localWorkerProtocol";

export const MAX_REQUEST_BYTES = 1024 * 1024;
export const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
export const MAX_CONCURRENT_REQUESTS = 32;
const TIMEOUT_MS = 10_000;

export class LocalWorkerTransportError extends Error {
  readonly code?: string;
  readonly uncertain: boolean;

  constructor(
    message: string,
    options: { code?: string; uncertain?: boolean } = {},
  ) {
    super(message);
    this.name = "LocalWorkerTransportError";
    this.code = options.code;
    this.uncertain = options.uncertain ?? false;
  }
}

function writeError(res: http.ServerResponse, status: number, message: string) {
  if (res.destroyed || res.writableEnded) return;
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.writeHead(status, {
    "content-type": "application/json",
    connection: "close",
  });
  res.end(JSON.stringify({ error: { message } }));
}

export interface ServeWorkerTransportOptions {
  socketPath: string;
  handle(
    request: LocalWorkerRequest,
    signal: AbortSignal,
  ): Promise<WorkerSnapshot>;
}

export interface WorkerTransportServer {
  close(): Promise<void>;
}

// The caller holds the host lock throughout bind, service and endpoint cleanup.
export async function serveWorkerTransport({
  socketPath,
  handle,
}: ServeWorkerTransportOptions): Promise<WorkerTransportServer> {
  let closing = false;
  let listening = false;
  let closed: Promise<void> | undefined;
  const requests = new Set<AbortController>();
  const sockets = new Set<Socket>();
  const server = http.createServer((req, res) => {
    if (closing || requests.size >= MAX_CONCURRENT_REQUESTS) {
      writeError(res, 503, "Worker endpoint is unavailable or saturated");
      return;
    }
    if (req.method !== "POST" || req.url !== "/rpc") {
      writeError(res, 404, "Unknown worker endpoint");
      return;
    }
    const controller = new AbortController();
    requests.add(controller);
    const disconnect = () => {
      if (!res.writableEnded) controller.abort();
    };
    const timer = setTimeout(() => {
      controller.abort();
      req.destroy();
      res.destroy();
    }, TIMEOUT_MS);
    req.once("aborted", disconnect);
    res.once("close", disconnect);
    void (async () => {
      try {
        const chunks: Buffer[] = [];
        let bytes = 0;
        for await (const chunk of req) {
          const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          bytes += data.length;
          if (bytes > MAX_REQUEST_BYTES) {
            writeError(res, 413, "Worker request body is too large");
            return;
          }
          chunks.push(data);
        }
        let request: LocalWorkerRequest;
        try {
          request = parseWorkerRequest(
            JSON.parse(Buffer.concat(chunks).toString("utf8")),
          );
        } catch (cause) {
          writeError(
            res,
            400,
            cause instanceof Error ? cause.message : "Invalid worker request",
          );
          return;
        }
        controller.signal.throwIfAborted();
        const value = await handle(request, controller.signal);
        if (res.destroyed) return;
        const body = JSON.stringify(value);
        const length = Buffer.byteLength(body);
        if (length > MAX_RESPONSE_BYTES) {
          writeError(res, 500, "Worker response exceeded its bound");
          return;
        }
        res.writeHead(200, {
          "content-type": "application/json",
          "content-length": length,
          connection: "close",
        });
        res.end(body);
      } catch (cause) {
        writeError(
          res,
          500,
          cause instanceof Error ? cause.message : "Worker request failed",
        );
      } finally {
        clearTimeout(timer);
        requests.delete(controller);
        req.off("aborted", disconnect);
        res.off("close", disconnect);
      }
    })();
  });
  server.headersTimeout = TIMEOUT_MS;
  server.requestTimeout = TIMEOUT_MS;
  server.on("connection", (socket) => {
    if (closing || sockets.size >= MAX_CONCURRENT_REQUESTS * 2) {
      socket.destroy();
      return;
    }
    sockets.add(socket);
    socket.setTimeout(TIMEOUT_MS, () => socket.destroy());
    socket.once("close", () => sockets.delete(socket));
  });

  const close = () => {
    closed ??= (async () => {
      closing = true;
      for (const controller of requests) controller.abort();
      for (const socket of sockets) socket.destroy();
      if (!listening) return;
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      await unlink(socketPath).catch((cause: NodeJS.ErrnoException) => {
        if (cause.code !== "ENOENT") throw cause;
      });
    })();
    return closed;
  };
  try {
    await new Promise<void>((resolve, reject) => {
      server.on("error", reject);
      server.listen(socketPath, () => {
        listening = true;
        resolve();
      });
    });
    await chmod(socketPath, 0o600);
    return { close };
  } catch (cause) {
    await close();
    throw cause;
  }
}

export interface WorkerRequestOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
}

// A failed acknowledgement never triggers a second mutation request.
export function workerRequest(
  socketPath: string,
  request: LocalWorkerRequest,
  { signal, timeoutMs = TIMEOUT_MS }: WorkerRequestOptions = {},
): Promise<WorkerSnapshot> {
  const mutation = request.method !== "snapshot" && request.method !== "watch";
  const body = JSON.stringify(request);
  if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) {
    return Promise.reject(
      new LocalWorkerTransportError("Worker request exceeds its bound"),
    );
  }
  if (signal?.aborted) {
    return Promise.reject(
      new LocalWorkerTransportError("Worker request was cancelled"),
    );
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    let connected = false;
    let diagnostic: Socket | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = () =>
      fail(
        new LocalWorkerTransportError("Worker request was cancelled", {
          uncertain: mutation,
        }),
      );
    const cleanup = () => {
      clearTimeout(timer);
      diagnostic?.destroy();
      signal?.removeEventListener("abort", onAbort);
    };
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      req.destroy();
      reject(error);
    };
    const req = http.request(
      {
        socketPath,
        path: "/rpc",
        method: "POST",
        agent: false,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          connection: "close",
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          if (settled) return;
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            fail(
              new LocalWorkerTransportError(
                "Worker response exceeded its bound",
                { uncertain: mutation },
              ),
            );
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          if (settled) return;
          try {
            const parsed: unknown = JSON.parse(
              Buffer.concat(chunks).toString("utf8"),
            );
            if (res.statusCode !== 200) {
              const message =
                typeof parsed === "object" &&
                parsed !== null &&
                "error" in parsed &&
                typeof parsed.error === "object" &&
                parsed.error !== null &&
                "message" in parsed.error &&
                typeof parsed.error.message === "string"
                  ? parsed.error.message
                  : `Worker returned HTTP ${res.statusCode}`;
              fail(
                new LocalWorkerTransportError(message, {
                  uncertain:
                    mutation &&
                    res.statusCode !== 400 &&
                    res.statusCode !== 503,
                }),
              );
              return;
            }
            const snapshot = parseWorkerSnapshot(parsed);
            settled = true;
            cleanup();
            resolve(snapshot);
          } catch (cause) {
            fail(
              new LocalWorkerTransportError(
                cause instanceof Error
                  ? cause.message
                  : "Malformed worker response",
                { uncertain: mutation },
              ),
            );
          }
        });
        res.on("error", (cause) =>
          fail(
            new LocalWorkerTransportError(cause.message, {
              uncertain: mutation,
            }),
          ),
        );
        res.on("aborted", () =>
          fail(
            new LocalWorkerTransportError("Worker response was interrupted", {
              uncertain: mutation,
            }),
          ),
        );
      },
    );
    req.once("socket", (socket) =>
      socket.once("connect", () => {
        connected = true;
      }),
    );
    req.once("error", (cause: NodeJS.ErrnoException) => {
      // Bun collapses Unix connect failures; a native socket recovers the errno.
      if (cause.code === "FailedToOpenSocket" && !settled) {
        diagnostic = createConnection({ path: socketPath });
        const unavailable = (code?: string) =>
          fail(
            new LocalWorkerTransportError(cause.message, {
              ...(code === "ENOENT" || code === "ECONNREFUSED" ? { code } : {}),
              uncertain: mutation,
            }),
          );
        diagnostic.once("connect", () => unavailable());
        diagnostic.once("error", (error: NodeJS.ErrnoException) =>
          unavailable(error.code),
        );
        diagnostic.setTimeout(Math.min(1_000, timeoutMs), () => unavailable());
        return;
      }
      const absent =
        !connected &&
        (cause.code === "ENOENT" || cause.code === "ECONNREFUSED");
      fail(
        new LocalWorkerTransportError(
          `Worker endpoint request failed: ${cause.message}`,
          {
            ...(absent ? { code: cause.code } : {}),
            uncertain: mutation && !absent,
          },
        ),
      );
    });
    timer = setTimeout(
      () =>
        fail(
          new LocalWorkerTransportError(
            `Worker request timed out after ${timeoutMs}ms`,
            { uncertain: mutation },
          ),
        ),
      timeoutMs,
    );
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
      return;
    }
    req.end(body);
  });
}
