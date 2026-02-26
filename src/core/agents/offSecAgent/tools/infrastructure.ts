/**
 * Infrastructure Lifecycle Manager
 *
 * Central manager for attacker infrastructure within a session:
 * - Port allocation from a configurable range
 * - Tunnel management via cloudflared
 * - Activity logging to session evidence
 * - Auto-cleanup on abort/session end
 */

import { createServer, type Server, type IncomingMessage } from "http";
import { createSocket, type Socket as DgramSocket } from "dgram";
import { spawn, type ChildProcess } from "child_process";
import { appendFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface InfraServer {
  id: string;
  type: "http" | "dns";
  port: number;
  localUrl: string;
  publicUrl?: string;
  server: Server | DgramSocket;
  tunnelProcess?: ChildProcess;
  interactions: Interaction[];
  createdAt: number;
  timeout?: ReturnType<typeof setTimeout>;
}

export interface Interaction {
  timestamp: number;
  type: "http-request" | "dns-query";
  sourceIp: string;
  sourcePort?: number;
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  body?: string;
  query?: string;
  queryType?: string;
}

export interface InfraConfig {
  /** Port range for local servers */
  portRange: [number, number];
  /** Session evidence directory for logging */
  evidenceDir: string;
  /** AbortSignal for cleanup */
  abortSignal?: AbortSignal;
}

// ---------------------------------------------------------------------------
// InfrastructureManager
// ---------------------------------------------------------------------------

export class InfrastructureManager {
  private servers: Map<string, InfraServer> = new Map();
  private allocatedPorts: Set<number> = new Set();
  private nextId = 1;
  private config: InfraConfig;
  private logPath: string;

  constructor(config: InfraConfig) {
    this.config = config;
    this.logPath = join(config.evidenceDir, "infra-log.jsonl");

    // Ensure evidence directory exists
    if (!existsSync(config.evidenceDir)) {
      mkdirSync(config.evidenceDir, { recursive: true });
    }

    // Auto-cleanup on abort
    if (config.abortSignal) {
      config.abortSignal.addEventListener(
        "abort",
        () => {
          this.shutdownAll();
        },
        { once: true },
      );
    }
  }

  // -------------------------------------------------------------------------
  // Port allocation
  // -------------------------------------------------------------------------

  allocatePort(): number {
    const [min, max] = this.config.portRange;
    for (let port = min; port <= max; port++) {
      if (!this.allocatedPorts.has(port)) {
        this.allocatedPorts.add(port);
        return port;
      }
    }
    throw new Error(
      `No available ports in range ${min}-${max}. Stop some servers first.`,
    );
  }

  releasePort(port: number): void {
    this.allocatedPorts.delete(port);
  }

  // -------------------------------------------------------------------------
  // HTTP server creation
  // -------------------------------------------------------------------------

  async startHttpServer(opts: {
    port?: number;
    timeout?: number;
    expose?: boolean;
    handler?: (
      req: IncomingMessage,
      interactions: Interaction[],
    ) => { status: number; headers: Record<string, string>; body: string };
  }): Promise<InfraServer> {
    const port = opts.port ?? this.allocatePort();
    const id = `infra-${this.nextId++}`;

    const interactions: Interaction[] = [];

    const server = createServer((req, res) => {
      // Collect body
      const chunks: Buffer[] = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf-8");
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(req.headers)) {
          if (typeof v === "string") headers[k] = v;
          else if (Array.isArray(v)) headers[k] = v.join(", ");
        }

        const interaction: Interaction = {
          timestamp: Date.now(),
          type: "http-request",
          sourceIp: req.socket.remoteAddress ?? "unknown",
          sourcePort: req.socket.remotePort,
          method: req.method,
          path: req.url,
          headers,
          body: body.substring(0, 10000),
        };

        interactions.push(interaction);
        this.logInteraction(id, interaction);

        // Custom handler or default
        if (opts.handler) {
          const resp = opts.handler(req, interactions);
          res.writeHead(resp.status, resp.headers);
          res.end(resp.body);
        } else {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("OK");
        }
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.listen(port, "0.0.0.0", () => resolve());
      server.on("error", reject);
    });

    const infraServer: InfraServer = {
      id,
      type: "http",
      port,
      localUrl: `http://localhost:${port}`,
      server,
      interactions,
      createdAt: Date.now(),
    };

    // Auto-shutdown timeout
    if (opts.timeout) {
      infraServer.timeout = setTimeout(() => {
        this.stopServer(id);
      }, opts.timeout * 1000);
    }

    // Expose via cloudflared tunnel
    if (opts.expose !== false) {
      try {
        const publicUrl = await this.startTunnel(port);
        infraServer.publicUrl = publicUrl;
      } catch {
        // Tunnel failed — continue with localhost only
      }
    }

    this.servers.set(id, infraServer);
    return infraServer;
  }

  // -------------------------------------------------------------------------
  // DNS server creation
  // -------------------------------------------------------------------------

  async startDnsServer(opts: {
    port?: number;
    timeout?: number;
  }): Promise<InfraServer> {
    const port = opts.port ?? this.allocatePort();
    const id = `infra-${this.nextId++}`;

    const interactions: Interaction[] = [];

    const server = createSocket("udp4");

    server.on("message", (msg, rinfo) => {
      // Parse basic DNS query name from the message
      let queryName = "";
      try {
        // Skip DNS header (12 bytes), then read QNAME labels
        let offset = 12;
        const labels: string[] = [];
        while (offset < msg.length) {
          const len = msg[offset]!;
          if (len === 0) break;
          offset++;
          labels.push(msg.subarray(offset, offset + len).toString("ascii"));
          offset += len;
        }
        queryName = labels.join(".");
      } catch {
        queryName = "(parse-error)";
      }

      const interaction: Interaction = {
        timestamp: Date.now(),
        type: "dns-query",
        sourceIp: rinfo.address,
        sourcePort: rinfo.port,
        query: queryName,
      };

      interactions.push(interaction);
      this.logInteraction(id, interaction);

      // Send a basic NXDOMAIN response (keeps the original query ID)
      if (msg.length >= 2) {
        const response = Buffer.alloc(msg.length);
        msg.copy(response);
        response[2] = 0x81; // QR=1, RD=1
        response[3] = 0x83; // RA=1, RCODE=NXDOMAIN
        server.send(response, rinfo.port, rinfo.address);
      }
    });

    await new Promise<void>((resolve, reject) => {
      server.bind(port, "0.0.0.0", () => resolve());
      server.on("error", reject);
    });

    const infraServer: InfraServer = {
      id,
      type: "dns",
      port,
      localUrl: `dns://localhost:${port}`,
      server,
      interactions,
      createdAt: Date.now(),
    };

    if (opts.timeout) {
      infraServer.timeout = setTimeout(() => {
        this.stopServer(id);
      }, opts.timeout * 1000);
    }

    this.servers.set(id, infraServer);
    return infraServer;
  }

  // -------------------------------------------------------------------------
  // Tunnel management (cloudflared)
  // -------------------------------------------------------------------------

  private async startTunnel(port: number): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const proc = spawn("cloudflared", [
        "tunnel",
        "--url",
        `http://localhost:${port}`,
      ]);

      let publicUrl = "";
      const timeout = setTimeout(() => {
        if (!publicUrl) {
          proc.kill();
          reject(new Error("Tunnel start timeout"));
        }
      }, 15000);

      const handleOutput = (data: Buffer) => {
        const text = data.toString();
        // cloudflared outputs the public URL to stderr
        const urlMatch = text.match(
          /https:\/\/[a-z0-9-]+\.trycloudflare\.com/,
        );
        if (urlMatch && !publicUrl) {
          publicUrl = urlMatch[0];
          clearTimeout(timeout);

          // Store the tunnel process with the corresponding server
          for (const server of this.servers.values()) {
            if (server.port === port && !server.tunnelProcess) {
              server.tunnelProcess = proc;
              break;
            }
          }

          resolve(publicUrl);
        }
      };

      proc.stderr.on("data", handleOutput);
      proc.stdout.on("data", handleOutput);

      proc.on("error", (err) => {
        clearTimeout(timeout);
        reject(
          new Error(
            `cloudflared not available: ${err.message}. Install with: brew install cloudflared`,
          ),
        );
      });

      proc.on("exit", (code) => {
        if (!publicUrl) {
          clearTimeout(timeout);
          reject(new Error(`cloudflared exited with code ${code}`));
        }
      });
    });
  }

  // -------------------------------------------------------------------------
  // Server management
  // -------------------------------------------------------------------------

  getServer(id: string): InfraServer | undefined {
    return this.servers.get(id);
  }

  getInteractions(id: string): Interaction[] {
    return this.servers.get(id)?.interactions ?? [];
  }

  listServers(): InfraServer[] {
    return Array.from(this.servers.values());
  }

  stopServer(id: string): boolean {
    const server = this.servers.get(id);
    if (!server) return false;

    // Clear timeout
    if (server.timeout) clearTimeout(server.timeout);

    // Kill tunnel
    if (server.tunnelProcess) {
      server.tunnelProcess.kill();
    }

    // Close server
    if (server.type === "http") {
      (server.server as Server).close();
    } else {
      (server.server as DgramSocket).close();
    }

    this.releasePort(server.port);
    this.servers.delete(id);
    return true;
  }

  shutdownAll(): void {
    for (const id of this.servers.keys()) {
      this.stopServer(id);
    }
  }

  // -------------------------------------------------------------------------
  // Logging
  // -------------------------------------------------------------------------

  private logInteraction(serverId: string, interaction: Interaction): void {
    try {
      const entry = JSON.stringify({ serverId, ...interaction });
      appendFileSync(this.logPath, entry + "\n");
    } catch {
      // Don't let logging failures break the server
    }
  }
}
