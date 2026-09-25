import { randomBytes, randomUUID } from "node:crypto";
import { appendFile, mkdir } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname } from "node:path";
import { targetFetch } from "../../../http/targetHeaders";
import type { SandboxOastLease } from "./sandbox";

const ROUTE_PREFIX = "/__apex_oast/";
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export type OastForwardRequest = {
  requestId: string;
  method: string;
  path: string;
  headers: Record<string, string | string[]>;
  body: Uint8Array;
  remoteAddress?: string;
};

export type OastForwardResponse = {
  status?: number;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
};

export type OastForwarder = (
  request: OastForwardRequest,
) => Promise<OastForwardResponse | undefined>;

type RegisteredRoute = {
  sessionId: string;
  eventsPath: string;
  callbackPort: number;
  forward: OastForwarder;
  writes: Promise<void>;
};

export type SessionOastRouterOptions = {
  bindHost?: string;
  port?: number;
  publicBaseUrl?: string;
  maxBodyBytes?: number;
  /** Platform delivers ingress through dispatch(); no local listening socket. */
  externalIngress?: boolean;
};

export type OastIngressRequest = {
  url: string;
  method?: string;
  headers?: Record<string, string | string[]>;
  body?: Uint8Array;
  remoteAddress?: string;
};

export type RegisterOastSessionInput = {
  sessionId: string;
  eventsPath: string;
  callbackPort: number;
  forward: OastForwarder;
};

export type RegisteredOastSession = SandboxOastLease & {
  dispose(): Promise<void>;
};

function normalizeHeaders(
  request: IncomingMessage,
): Record<string, string | string[]> {
  const headers: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(request.headers)) {
    if (value !== undefined) headers[name] = value;
  }
  return headers;
}

async function readBody(
  request: IncomingMessage,
  maxBodyBytes: number,
): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > maxBodyBytes) {
      throw new Error(`OAST request body exceeds ${maxBodyBytes} bytes`);
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

function responseBody(value: string | Uint8Array | undefined): Uint8Array {
  if (value === undefined) return new Uint8Array();
  return typeof value === "string" ? Buffer.from(value) : value;
}

export class SessionOastRouter {
  private readonly routes = new Map<string, RegisteredRoute>();
  private server?: Server;
  private baseUrl?: string;

  constructor(private readonly options: SessionOastRouterOptions = {}) {}

  async listen(): Promise<void> {
    if (this.server || this.baseUrl) return;
    if (this.options.externalIngress) {
      if (!this.options.publicBaseUrl) {
        throw new Error("externalIngress requires publicBaseUrl");
      }
      this.baseUrl = this.options.publicBaseUrl.replace(/\/$/, "");
      return;
    }
    const server = createServer((request, response) => {
      void this.handleRequest(request)
        .then((result) => {
          response.statusCode = result.status ?? 204;
          for (const [name, value] of Object.entries(result.headers ?? {})) {
            response.setHeader(name, value);
          }
          response.end(responseBody(result.body));
        })
        .catch((error) => {
          const tooLarge =
            error instanceof Error && error.message.includes("exceeds");
          response.statusCode = tooLarge ? 413 : 502;
          response.end(
            tooLarge ? "Callback body too large" : "Callback routing failed",
          );
        });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(
        this.options.port ?? 0,
        this.options.bindHost ?? "127.0.0.1",
        () => {
          server.off("error", reject);
          resolve();
        },
      );
    });
    this.server = server;
    const address = server.address() as AddressInfo;
    this.baseUrl = (
      this.options.publicBaseUrl ?? `http://127.0.0.1:${address.port}`
    ).replace(/\/$/, "");
  }

  async registerSession(
    input: RegisterOastSessionInput,
  ): Promise<RegisteredOastSession> {
    await this.listen();
    const token = randomBytes(24).toString("base64url");
    this.routes.set(token, { ...input, writes: Promise.resolve() });
    await mkdir(dirname(input.eventsPath), { recursive: true });

    return {
      callbackUrl: `${this.baseUrl}${ROUTE_PREFIX}${token}`,
      callbackPort: input.callbackPort,
      eventsPath: input.eventsPath,
      dispose: async () => {
        const route = this.routes.get(token);
        this.routes.delete(token);
        await route?.writes.catch(() => {});
      },
    };
  }

  async close(): Promise<void> {
    const server = this.server;
    const pendingWrites = [...this.routes.values()].map((route) =>
      route.writes.catch(() => {}),
    );
    this.server = undefined;
    this.baseUrl = undefined;
    this.routes.clear();
    if (server) {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      });
    }
    await Promise.all(pendingWrites);
  }

  /** Entry point for a hosted relay or platform ingress adapter. */
  async dispatch(incoming: OastIngressRequest): Promise<OastForwardResponse> {
    const body = incoming.body ?? new Uint8Array();
    const maxBodyBytes = this.options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
    if (body.byteLength > maxBodyBytes) {
      throw new Error(`OAST request body exceeds ${maxBodyBytes} bytes`);
    }
    return this.routeRequest({
      url: incoming.url,
      method: incoming.method ?? "GET",
      headers: incoming.headers ?? {},
      body,
      remoteAddress: incoming.remoteAddress,
    });
  }

  private async handleRequest(
    incoming: IncomingMessage,
  ): Promise<OastForwardResponse> {
    const body = await readBody(
      incoming,
      this.options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES,
    );
    return this.routeRequest({
      url: incoming.url ?? "/",
      method: incoming.method ?? "GET",
      headers: normalizeHeaders(incoming),
      body,
      remoteAddress: incoming.socket.remoteAddress,
    });
  }

  private async routeRequest(
    incoming: Required<
      Pick<OastIngressRequest, "url" | "method" | "headers" | "body">
    > &
      Pick<OastIngressRequest, "remoteAddress">,
  ): Promise<OastForwardResponse> {
    const parsed = new URL(incoming.url, "http://apex.invalid");
    if (!parsed.pathname.startsWith(ROUTE_PREFIX)) {
      return { status: 404, body: "Unknown callback route" };
    }
    const remainder = parsed.pathname.slice(ROUTE_PREFIX.length);
    const [token, ...suffixParts] = remainder.split("/");
    const route = this.routes.get(token);
    if (!route) return { status: 404, body: "Unknown callback route" };

    const suffix = `/${suffixParts.join("/")}${parsed.search}`;
    const requestId = `oast_${randomUUID()}`;
    const forwardedRequest: OastForwardRequest = {
      requestId,
      method: incoming.method,
      path: suffix,
      headers: incoming.headers,
      body: incoming.body,
      remoteAddress: incoming.remoteAddress,
    };

    let forwarded: OastForwardResponse | undefined;
    let forwardError: string | undefined;
    try {
      forwarded = await route.forward(forwardedRequest);
    } catch (error) {
      forwardError = error instanceof Error ? error.message : String(error);
    }

    const record = {
      type: "oast-request",
      timestamp: new Date().toISOString(),
      requestId,
      sessionId: route.sessionId,
      callbackPort: route.callbackPort,
      method: forwardedRequest.method,
      path: forwardedRequest.path,
      headers: forwardedRequest.headers,
      bodyBase64: Buffer.from(incoming.body).toString("base64"),
      remoteAddress: forwardedRequest.remoteAddress,
      forwarded: forwardError === undefined,
      ...(forwardError ? { forwardError } : {}),
    };
    route.writes = route.writes.then(() =>
      appendFile(route.eventsPath, `${JSON.stringify(record)}\n`, "utf8"),
    );
    await route.writes;

    if (forwardError) {
      return {
        status: 202,
        headers: { "x-apex-oast-recorded": "true" },
        body: "Callback recorded; listener delivery failed",
      };
    }
    return forwarded ?? { status: 204 };
  }
}

/** Forward an OAST request to a listener address exposed by a trusted sandbox controller. */
export function createHttpOastForwarder(
  listenerBaseUrl: string,
): OastForwarder {
  const baseUrl = listenerBaseUrl.replace(/\/$/, "");
  return async (request) => {
    const headers = new Headers();
    for (const [name, value] of Object.entries(request.headers)) {
      if (HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
      for (const item of Array.isArray(value) ? value : [value]) {
        headers.append(name, item);
      }
    }
    headers.set("x-apex-oast-request-id", request.requestId);
    const body =
      request.method === "GET" || request.method === "HEAD"
        ? undefined
        : (request.body as BodyInit);
    const response = await targetFetch({}, `${baseUrl}${request.path}`, {
      method: request.method,
      headers,
      body,
    });
    return {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") ?? "text/plain",
      },
      body: new Uint8Array(await response.arrayBuffer()),
    };
  };
}
