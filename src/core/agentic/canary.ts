import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { CanaryHandle, CanaryHit } from "./types";

/**
 * Out-of-band callback detector. Payloads embed a unique URL/token; when the
 * agent (or a tool / connected action / handed-off agent it invokes) hits it, we
 * record the hit and attribute it to the case. `wasTriggered` is the
 * deterministic exploit signal for exfil / tool-abuse / agent-handoff cases.
 */
export interface CanaryProvider {
  start(): Promise<void>;
  mint(): CanaryHandle;
  hits(token: string): CanaryHit[];
  wasTriggered(token: string): boolean;
  stop(): Promise<void>;
}

function mintToken(): string {
  return randomBytes(9).toString("hex");
}

/**
 * Local HTTP collector (node:http so it runs under both Node and Bun). For a
 * remote agent's egress to reach it, expose the port via a tunnel and set the
 * canary `publicUrl` to the public address.
 */
export class LocalCanaryServer implements CanaryProvider {
  private readonly received = new Map<string, CanaryHit[]>();
  private readonly server: Server;

  constructor(
    private readonly publicUrl: string,
    private readonly port: number,
  ) {
    this.server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://localhost");
      const match = url.pathname.match(/^\/c\/([a-f0-9]+)/);
      if (!match) {
        res.writeHead(200);
        res.end("ok");
        return;
      }
      const token = match[1]!;
      let body = "";
      req.on("data", (chunk) => {
        if (body.length < 8000) body += chunk;
      });
      req.on("end", () => {
        const hit: CanaryHit = {
          token,
          at: new Date().toISOString(),
          method: req.method ?? "GET",
          path: url.pathname,
          query: url.search,
          body: body.slice(0, 4000),
        };
        const list = this.received.get(token) ?? [];
        list.push(hit);
        this.received.set(token, list);
        res.writeHead(200);
        res.end("ok");
      });
    });
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      this.server.once("error", onError);
      this.server.listen(this.port, () => {
        this.server.off("error", onError);
        resolve();
      });
    });
  }

  mint(): CanaryHandle {
    const token = mintToken();
    return { token, url: `${this.publicUrl}/c/${token}` };
  }

  hits(token: string): CanaryHit[] {
    return this.received.get(token) ?? [];
  }

  wasTriggered(token: string): boolean {
    return (this.received.get(token)?.length ?? 0) > 0;
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}

/** No-op collector for dry runs — mints URLs but never fires. */
export class NullCanary implements CanaryProvider {
  constructor(private readonly publicUrl: string) {}

  async start(): Promise<void> {}

  mint(): CanaryHandle {
    const token = mintToken();
    return { token, url: `${this.publicUrl}/c/${token}` };
  }

  hits(): CanaryHit[] {
    return [];
  }

  wasTriggered(): boolean {
    return false;
  }

  async stop(): Promise<void> {}
}
