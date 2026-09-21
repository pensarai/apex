import { exec, execFile } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { createServer as createNetServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildWindowsCurlCommand,
  type WindowsCurlOptions,
} from "./windowsCurl";

const execFileAsync = promisify(execFile);
const execAsync = promisify(exec);

const BASE_OPTS: WindowsCurlOptions = {
  url: "https://example.com/api",
  method: "GET",
  headers: { "Content-Type": "application/json" },
  followRedirects: false,
  timeoutSeconds: 10,
  maxBytes: 5 * 1024 * 1024,
  exitMarker: "__APEX_abc123_CURL_EXIT_",
};

const NONCE = "__APEX_abc123_CURL_EXIT_";

describe("buildWindowsCurlCommand generation (any OS)", () => {
  it("returns a fixed-length command plus request data in envVars", () => {
    const { command, envVars } = buildWindowsCurlCommand(BASE_OPTS);
    expect(command).toMatch(
      /^powershell\.exe -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$/,
    );
    expect(envVars.APEX_HTTP_CURL_ARGS).toBeTruthy();
    expect(envVars.APEX_HTTP_MARKER).toBe(NONCE);
    expect(envVars.APEX_HTTP_MAX_BYTES).toBe(String(BASE_OPTS.maxBytes));
    expect(envVars.APEX_HTTP_BUDGET_MS).toBe("10000");
    expect(envVars.APEX_HTTP_BODY_COUNT).toBe("0");
    expect(envVars.APEX_HTTP_BODY_LENGTH).toBe("0");
  });

  it("encoded command stays under cmd.exe's 8191-char limit", () => {
    const { command } = buildWindowsCurlCommand(BASE_OPTS);
    expect(command.length).toBeLessThan(8191);
  });

  it("command length is constant regardless of request body/URL size", () => {
    const small = buildWindowsCurlCommand(BASE_OPTS);
    const big = buildWindowsCurlCommand({
      ...BASE_OPTS,
      url: `https://example.com/${"x".repeat(2000)}`,
      body: "y".repeat(5000),
    });
    expect(small.command.length).toBe(big.command.length);
  });

  it("CRT-quoted argv contains --no-buffer, method, headers, --max-time, URL", () => {
    const { envVars } = buildWindowsCurlCommand(BASE_OPTS);
    const args = envVars.APEX_HTTP_CURL_ARGS;
    expect(args).toContain("--no-buffer");
    expect(args).toContain("-X GET");
    expect(args).toContain("Content-Type: application/json");
    expect(args).toContain("--max-time 10");
    expect(args).toContain(BASE_OPTS.url);
  });

  it("followRedirects=false omits -L; true includes it in the argv", () => {
    const noFollow = buildWindowsCurlCommand({
      ...BASE_OPTS,
      followRedirects: false,
    });
    expect(noFollow.envVars.APEX_HTTP_CURL_ARGS).not.toMatch(/\s-L\s/);
    const follow = buildWindowsCurlCommand({
      ...BASE_OPTS,
      followRedirects: true,
    });
    expect(follow.envVars.APEX_HTTP_CURL_ARGS).toMatch(/\s-L\s/);
  });

  it("always sets BODY_COUNT/LENGTH 0 when no body; chunks present when given", () => {
    const noBody = buildWindowsCurlCommand(BASE_OPTS);
    expect(noBody.envVars.APEX_HTTP_BODY_COUNT).toBe("0");
    expect(noBody.envVars.APEX_HTTP_BODY_LENGTH).toBe("0");
    expect(noBody.envVars.APEX_HTTP_BODY_0).toBeUndefined();

    const small = buildWindowsCurlCommand({ ...BASE_OPTS, body: "payload" });
    const smallB64 = Buffer.from("payload", "utf8").toString("base64");
    expect(small.envVars.APEX_HTTP_BODY_COUNT).toBe("1");
    expect(small.envVars.APEX_HTTP_BODY_LENGTH).toBe(String(smallB64.length));
    expect(small.envVars.APEX_HTTP_BODY_0).toBe(smallB64);
  });

  it("bodies larger than one chunk split into BODY_0, BODY_1, ... each <=6000 chars", () => {
    const body = "z".repeat(10_000);
    const { envVars } = buildWindowsCurlCommand({ ...BASE_OPTS, body });
    const fullB64 = Buffer.from(body, "utf8").toString("base64");
    expect(envVars.APEX_HTTP_BODY_COUNT).toBe(
      String(Math.ceil(fullB64.length / 6000)),
    );
    expect(envVars.APEX_HTTP_BODY_LENGTH).toBe(String(fullB64.length));
    // Chunks concatenate to the full base64, each within the cmd.exe limit.
    let joined = "";
    for (let i = 0; i < Number(envVars.APEX_HTTP_BODY_COUNT); i++) {
      const chunk = envVars[`APEX_HTTP_BODY_${i}`];
      expect(chunk).toBeTruthy();
      expect(chunk.length).toBeLessThanOrEqual(6000);
      joined += chunk;
    }
    expect(joined).toBe(fullB64);
  });

  it("hostile data stays inside envVars, not the command string", () => {
    const { command, envVars } = buildWindowsCurlCommand({
      ...BASE_OPTS,
      url: "https://example.com/path?a=1&echo sentinel; cat /etc/passwd",
      headers: { "X-Evil": '"; echo injected && dir C:\\; echo "' },
    });
    expect(command).not.toContain("cat /etc/passwd");
    expect(command).not.toContain("echo injected");
    expect(envVars.APEX_HTTP_CURL_ARGS).toContain("echo sentinel");
  });

  it("decoded script uses env vars, Process.Start, and a fixed 64KiB buffer", () => {
    const { command } = buildWindowsCurlCommand(BASE_OPTS);
    const b64 = command.replace(
      /^powershell\.exe -NoProfile -NonInteractive -EncodedCommand /,
      "",
    );
    const script = Buffer.from(b64, "base64").toString("utf16le");
    expect(script).toContain(
      "[Environment]::GetEnvironmentVariable('APEX_HTTP_CURL_ARGS')",
    );
    expect(script).toContain("[Diagnostics.Process]::Start");
    expect(script).toContain("$pi.FileName='curl.exe'");
    expect(script).toContain("$buf=New-Object byte[] 65536");
    expect(script).toContain("$os.Write($buf,0,$emit)");
    expect(script).not.toContain("RedirectStandardError");
    expect(script).not.toContain("ReadToEnd");
  });

  it("decoded script validates chunk count and total length before any HTTP", () => {
    const { command } = buildWindowsCurlCommand(BASE_OPTS);
    const b64 = command.replace(
      /^powershell\.exe -NoProfile -NonInteractive -EncodedCommand /,
      "",
    );
    const script = Buffer.from(b64, "base64").toString("utf16le");
    expect(script).toContain("APEX_HTTP_BODY_COUNT");
    expect(script).toContain("APEX_HTTP_BODY_LENGTH");
    expect(script).toContain("APEX_HTTP_BODY_$i");
    expect(script).toContain("missing body chunk");
    expect(script).toContain("body chunk length mismatch");
    // Reconstructs via StringBuilder, validates BEFORE Process.Start.
    const sbIdx = script.indexOf("Text.StringBuilder");
    const startIdx = script.indexOf("[Diagnostics.Process]::Start");
    expect(sbIdx).toBeGreaterThan(-1);
    expect(sbIdx).toBeLessThan(startIdx);
    // Length guard is outside the count>0 block — count0/positive-length also rejects.
    const guardIdx = script.indexOf("body chunk length mismatch");
    const countBlockEnd = script.indexOf(
      "}",
      script.indexOf("$body=$sb.ToString()"),
    );
    expect(guardIdx).toBeGreaterThan(countBlockEnd);
  });

  it("nested finally: process cleanup always runs then temp file always deleted", () => {
    const { command } = buildWindowsCurlCommand(BASE_OPTS);
    const b64 = command.replace(
      /^powershell\.exe -NoProfile -NonInteractive -EncodedCommand /,
      "",
    );
    const script = Buffer.from(b64, "base64").toString("utf16le");
    // Kill catch only suppresses if HasExited (race), otherwise rethrows.
    expect(script).toContain(
      "try{$p.Kill()}catch{if(-not $p.HasExited){throw}}",
    );
    expect(script).toContain("throw 'curl cleanup unconfirmed'");
    // Dispose always runs (inner finally), temp file always deleted (outer).
    expect(script).toContain("$p.Dispose()");
    expect(script).toContain("[IO.File]::Delete($tf)");
    expect(script).not.toContain("Remove-Item $tf");
    expect(script).not.toContain("SilentlyContinue");
    // No invalid label syntax.
    expect(script).not.toContain("try{finally:");
  });
});

// ---------------------------------------------------------------------------
// Windows-only real execution tests (it.skipIf on non-Win32).
// ---------------------------------------------------------------------------
describe("buildWindowsCurlCommand execution (Windows only)", () => {
  const isWin = process.platform === "win32";
  const servers: Server[] = [];
  const netServers: import("node:net").Server[] = [];
  const sockets: Socket[] = [];
  const scratchDirs: string[] = [];

  afterEach(async () => {
    // Force close accepted sockets before awaiting server.close to avoid
    // teardown hangs on stalled connections.
    for (const s of sockets.splice(0)) s.destroy();
    for (const s of servers.splice(0)) {
      await new Promise<void>((r) => s.close(() => r()));
    }
    for (const s of netServers.splice(0)) {
      await new Promise<void>((r) => s.close(() => r()));
    }
    for (const d of scratchDirs.splice(0)) {
      rmSync(d, { recursive: true, force: true });
    }
  });

  async function startServer(
    handler: (
      req: import("node:http").IncomingMessage,
      res: import("node:http").ServerResponse,
    ) => void,
  ): Promise<number> {
    const server = createServer(handler);
    server.on("connection", (s: Socket) => sockets.push(s));
    servers.push(server);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    return (server.address() as { port: number }).port;
  }

  async function startRawServer(
    responder: (socket: Socket) => void,
  ): Promise<number> {
    const server = createNetServer((socket) => {
      sockets.push(socket);
      responder(socket);
    });
    netServers.push(server);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    return (server.address() as { port: number }).port;
  }

  function tempScratchDir(): string {
    const dir = mkdtempSync(join(tmpdir(), "apex-wincurl-"));
    scratchDirs.push(dir);
    return dir;
  }

  async function runDirect(
    opts: WindowsCurlOptions,
    tempDir?: string,
  ): Promise<{ stdout: Buffer; stderr: string; exitCode: number }> {
    const { command, envVars } = buildWindowsCurlCommand(opts);
    const parts = command.split(" ");
    const env: NodeJS.ProcessEnv = { ...process.env, ...envVars };
    if (tempDir) {
      env.TEMP = tempDir;
      env.TMP = tempDir;
    }
    try {
      const { stdout, stderr } = await execFileAsync(parts[0], parts.slice(1), {
        timeout: (opts.timeoutSeconds + 15) * 1000,
        maxBuffer: 16 * 1024 * 1024,
        encoding: "buffer",
        env,
      });
      return {
        stdout: stdout as Buffer,
        stderr: (stderr as Buffer)?.toString("utf8") ?? "",
        exitCode: 0,
      };
    } catch (err: unknown) {
      const e = err as {
        stdout?: Buffer;
        stderr?: Buffer;
        code?: number | string;
        killed?: boolean;
        signal?: string;
      };
      // Surface how the child failed when stderr is empty (e.g. a timing
      // kill) — exit code, kill status, and signal, without dumping env.
      const diagnostics = `code=${e.code} killed=${e.killed} signal=${e.signal ?? "none"}`;
      const stderrText = (e.stderr as Buffer)?.toString("utf8") ?? "";
      return {
        stdout: (e.stdout as Buffer) ?? Buffer.alloc(0),
        stderr: stderrText || `child failed without stderr (${diagnostics})`,
        exitCode: typeof e.code === "number" ? e.code : 1,
      };
    }
  }

  async function runViaCmd(
    opts: WindowsCurlOptions,
  ): Promise<{ stdout: Buffer; stderr: string; exitCode: number }> {
    const { command, envVars } = buildWindowsCurlCommand(opts);
    const env: NodeJS.ProcessEnv = { ...process.env, ...envVars };
    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout: (opts.timeoutSeconds + 15) * 1000,
        maxBuffer: 16 * 1024 * 1024,
        encoding: "buffer",
        env,
        windowsHide: true,
      });
      return {
        stdout: stdout as Buffer,
        stderr: (stderr as Buffer)?.toString("utf8") ?? "",
        exitCode: 0,
      };
    } catch (err: unknown) {
      const e = err as {
        stdout?: Buffer;
        stderr?: Buffer;
        code?: number | string;
        killed?: boolean;
        signal?: string;
      };
      const diagnostics = `code=${e.code} killed=${e.killed} signal=${e.signal ?? "none"}`;
      const stderrText = (e.stderr as Buffer)?.toString("utf8") ?? "";
      return {
        stdout: (e.stdout as Buffer) ?? Buffer.alloc(0),
        stderr: stderrText || `child failed without stderr (${diagnostics})`,
        exitCode: typeof e.code === "number" ? e.code : 1,
      };
    }
  }

  it.skipIf(!isWin)(
    "normal 200: stdout exactly equals wire bytes + marker (raw net server)",
    async () => {
      const body = Buffer.from("héllo\r\nwörld\r\n", "utf8");
      const wire = Buffer.concat([
        Buffer.from(
          `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\n\r\n`,
          "utf8",
        ),
        body,
      ]);
      const port = await startRawServer((socket) => {
        socket.once("data", () => socket.end(wire));
      });
      const { stdout, stderr, exitCode } = await runDirect({
        ...BASE_OPTS,
        url: `http://127.0.0.1:${port}/raw`,
        timeoutSeconds: 15,
      });
      // Include stderr so a child timeout/kill is diagnosable from the
      // assertion message instead of a bare expected-0-received-1.
      if (exitCode !== 0) {
        expect.fail(`wrapper exit ${exitCode}, stderr: ${stderr.slice(-300)}`);
      }
      // stdout is exactly wire + '\n' + marker + '0' + '\n'.
      const expected = Buffer.concat([
        wire,
        Buffer.from(`\n${NONCE}0\n`, "utf8"),
      ]);
      expect(stdout.equals(expected)).toBe(true);
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "normal 200 through cmd.exe /d /s /c (adapter shell parsing)",
    async () => {
      const port = await startServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("cmd-route-ok");
      });
      const { stdout, exitCode } = await runViaCmd({
        ...BASE_OPTS,
        url: `http://127.0.0.1:${port}/cmd`,
        timeoutSeconds: 15,
      });
      expect(exitCode).toBe(0);
      const out = stdout.toString("utf8");
      expect(out).toContain("cmd-route-ok");
      expect(out).toMatch(new RegExp(`\\n${NONCE}0\\n$`));
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "hostile header value reaches the server as the exact original string",
    async () => {
      const evilValue = '"; echo sentinel && dir C:\\ | find "';
      let received = "";
      const port = await startServer((req, res) => {
        received = (req.headers["x-evil"] as string) ?? "";
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("ok");
      });
      const { exitCode } = await runDirect({
        ...BASE_OPTS,
        url: `http://127.0.0.1:${port}/hostile`,
        headers: { "X-Evil": evilValue, "X-Normal": "fine" },
        timeoutSeconds: 15,
      });
      expect(exitCode).toBe(0);
      expect(received).toBe(evilValue);
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "POST body reaches server exactly; temp dir empty after success",
    async () => {
      const tempDir = tempScratchDir();
      const requestBody = '{"username":"admin","password":"s3cret"}';
      let receivedBody = "";
      const port = await startServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          receivedBody = Buffer.concat(chunks).toString("utf8");
          res.writeHead(200, { "content-type": "application/json" });
          res.end('{"ok":true}');
        });
      });
      const { exitCode } = await runDirect(
        {
          ...BASE_OPTS,
          method: "POST",
          url: `http://127.0.0.1:${port}/login`,
          body: requestBody,
          headers: { "Content-Type": "application/json" },
          timeoutSeconds: 15,
        },
        tempDir,
      );
      expect(exitCode).toBe(0);
      expect(receivedBody).toBe(requestBody);
      expect(readdirSync(tempDir)).toEqual([]);
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "oversized response: exit 0, no marker, stdout exactly at the cap",
    async () => {
      const CAP = 2048;
      const port = await startServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("x".repeat(16 * 1024));
      });
      const { stdout, exitCode } = await runDirect({
        ...BASE_OPTS,
        url: `http://127.0.0.1:${port}/overflow`,
        maxBytes: CAP,
        timeoutSeconds: 15,
      });
      expect(exitCode).toBe(0);
      expect(stdout.toString("utf8")).not.toContain(NONCE);
      expect(stdout.length).toBe(CAP);
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "exact-cap: stdout exactly equals wire + marker (raw net server)",
    async () => {
      const body = Buffer.from("0123456789", "utf8");
      const wire = Buffer.concat([
        Buffer.from(
          `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\n\r\n`,
          "utf8",
        ),
        body,
      ]);
      const port = await startRawServer((socket) => {
        socket.once("data", () => socket.end(wire));
      });
      const { stdout, exitCode } = await runDirect({
        ...BASE_OPTS,
        url: `http://127.0.0.1:${port}/exact`,
        maxBytes: wire.length,
        timeoutSeconds: 15,
      });
      expect(exitCode).toBe(0);
      const expected = Buffer.concat([
        wire,
        Buffer.from(`\n${NONCE}0\n`, "utf8"),
      ]);
      expect(stdout.equals(expected)).toBe(true);
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "stalled read: wrapper timeout or curl exit-28 marker; both incomplete with partial preserved",
    async () => {
      const port = await startServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.write("partial-response-data");
        // Never ends.
      });
      const { stdout, exitCode } = await runDirect({
        ...BASE_OPTS,
        url: `http://127.0.0.1:${port}/stall`,
        timeoutSeconds: 5,
        maxBytes: 65536,
      });
      const out = stdout.toString("utf8");
      if (exitCode === 0) {
        expect(out).toMatch(new RegExp(`${NONCE}28\\n$`));
      } else {
        expect(out).not.toContain(NONCE);
      }
      expect(out).toContain("partial-response-data");
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "curl connection failure: nonzero curl exit in the marker",
    async () => {
      const { stdout, stderr, exitCode } = await runDirect({
        ...BASE_OPTS,
        url: "http://127.0.0.1:1/unreachable",
        timeoutSeconds: 10,
      });
      expect(exitCode).toBe(0);
      const out = stdout.toString("utf8");
      expect(out).toMatch(new RegExp(`${NONCE}(\\d+)\\n$`));
      const m = out.match(new RegExp(`${NONCE}(\\d+)\\n$`));
      expect(m).toBeTruthy();
      expect(parseInt(m?.[1] ?? "0", 10)).not.toBe(0);
      // curl --show-error writes diagnostics to inherited stderr.
      expect(stderr).toMatch(/curl:\s*\(\d+\)/);
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "temp dir empty after wrapper timeout (cleanup on all paths)",
    async () => {
      const tempDir = tempScratchDir();
      const port = await startServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.write("stall-with-body");
        // Never ends.
      });
      await runDirect(
        {
          ...BASE_OPTS,
          method: "POST",
          url: `http://127.0.0.1:${port}/stall-post`,
          body: '{"data":"timeout-test"}',
          headers: { "Content-Type": "application/json" },
          timeoutSeconds: 5,
          maxBytes: 65536,
        },
        tempDir,
      );
      expect(readdirSync(tempDir)).toEqual([]);
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "cmd-route POST body: env block >32767 works; server receives exact body",
    async () => {
      // Exercise a >32KiB Unicode environment through cmd.exe without
      // exceeding its per-variable limit.
      const body = `{"data":"${"A".repeat(80_000)}"}`;
      const built = buildWindowsCurlCommand({
        ...BASE_OPTS,
        method: "POST",
        url: "http://127.0.0.1:1/placeholder",
        body,
        headers: { "Content-Type": "application/json" },
        timeoutSeconds: 15,
      });
      const envBlockLen = Object.entries(built.envVars).reduce(
        (sum, [k, v]) => sum + k.length + v.length + 2,
        0,
      );
      expect(envBlockLen).toBeGreaterThan(32_767);
      // Every body chunk within the single-var 8191 limit.
      for (const [k, v] of Object.entries(built.envVars)) {
        if (k.startsWith("APEX_HTTP_BODY_") && k !== "APEX_HTTP_BODY_COUNT") {
          expect(v.length).toBeLessThanOrEqual(6000);
        }
      }

      let receivedBody = "";
      let requestArrived = false;
      const port = await startServer((req, res) => {
        requestArrived = true;
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          receivedBody = Buffer.concat(chunks).toString("utf8");
          res.writeHead(200, { "content-type": "application/json" });
          res.end('{"ok":true}');
        });
      });
      const { stdout, exitCode } = await runViaCmd({
        ...BASE_OPTS,
        method: "POST",
        url: `http://127.0.0.1:${port}/big-post`,
        body,
        headers: { "Content-Type": "application/json" },
        timeoutSeconds: 15,
      });
      expect(exitCode).toBe(0);
      expect(requestArrived).toBe(true);
      expect(receivedBody).toBe(body);
      expect(stdout.toString("utf8")).toMatch(new RegExp(`\\n${NONCE}0\\n$`));
    },
    60_000,
  );

  it.skipIf(!isWin)(
    "missing body chunk prevents any HTTP request (fails before Process.Start)",
    async () => {
      let requestArrived = false;
      const port = await startServer((_req, res) => {
        requestArrived = true;
        res.writeHead(200);
        res.end("should-not-reach");
      });
      const { command, envVars } = buildWindowsCurlCommand({
        ...BASE_OPTS,
        method: "POST",
        url: `http://127.0.0.1:${port}/missing-chunk`,
        body: "B".repeat(10_000),
        headers: { "Content-Type": "application/json" },
        timeoutSeconds: 10,
      });
      expect(Number(envVars.APEX_HTTP_BODY_COUNT)).toBeGreaterThan(1);
      const sabotaged = { ...envVars };
      delete sabotaged.APEX_HTTP_BODY_1;
      const parts = command.split(" ");
      await expect(
        execFileAsync(parts[0], parts.slice(1), {
          timeout: 20_000,
          maxBuffer: 16 * 1024 * 1024,
          encoding: "utf8",
          env: { ...process.env, ...sabotaged },
        }),
      ).rejects.toMatchObject({
        code: 1,
        stderr: expect.stringContaining("missing body chunk 1"),
      });
      expect(requestArrived).toBe(false);
    },
    45_000,
  );

  it.skipIf(!isWin)(
    "EOF with exhausted budget: marker emitted with curl exit 0 (not exit 1)",
    async () => {
      const port = await startServer((_req, res) => {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("eof-grace-test");
      });

      // Take the generated command, decode the script, inject a budget-zero
      // at EOF (right after $n=$t.Result), re-encode. This exercises the real
      // PS EOF path with an exhausted budget without timing sleeps.
      const built = buildWindowsCurlCommand({
        ...BASE_OPTS,
        url: `http://127.0.0.1:${port}/eof-grace`,
        timeoutSeconds: 15,
      });
      const b64 = built.command.replace(
        /^powershell\.exe -NoProfile -NonInteractive -EncodedCommand /,
        "",
      );
      const script = Buffer.from(b64, "base64").toString("utf16le");
      const resultLine = "$n=$t.Result";
      const idx = script.indexOf(resultLine);
      expect(idx).toBeGreaterThan(-1);
      const after = idx + resultLine.length;
      const injected = `${script.slice(0, after)}\nif($n -eq 0){$budgetMs=0}${script.slice(after)}`;
      const reEncoded = Buffer.from(injected, "utf16le").toString("base64");
      const parts = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        reEncoded,
      ];

      try {
        const { stdout } = await execFileAsync(parts[0], parts.slice(1), {
          timeout: 30_000,
          maxBuffer: 16 * 1024 * 1024,
          encoding: "buffer",
          env: { ...process.env, ...built.envVars },
        });
        const out = (stdout as Buffer).toString("utf8");
        // EOF observed + budget exhausted → marker with curl's real exit 0.
        expect(out).toContain("eof-grace-test");
        expect(out).toMatch(new RegExp(`\\n${NONCE}0\\n$`));
      } catch (err: unknown) {
        const e = err as { stdout?: Buffer; code?: number };
        const out = (e.stdout as Buffer)?.toString("utf8") ?? "";
        // Baseline (ec38f93) would fail here with exit 1 / no marker.
        expect.fail(
          `expected exit 0 with marker, got exit ${e.code}, output: ${out.slice(-200)}`,
        );
      }
    },
    45_000,
  );
});
