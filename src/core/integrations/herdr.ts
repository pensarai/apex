import { spawn } from "node:child_process";

export type HerdrState = "idle" | "working" | "blocked";

export interface HerdrReport {
  state: HerdrState;
  message?: string;
  session?: { id?: string; resumeArgv: string[] };
}

const SOURCE = "pensar-apex";
const AGENT = "apex";
const REPORT_TIMEOUT_MS = 1_000;
const INVALID_RESUME_CHARACTER = /['\p{Cc}]/u;
let sequence = 0;

function nextSequence(): string {
  sequence = Math.max(sequence + 1, Date.now() * 1_000);
  return String(sequence);
}

function validResumeArgv(argv: string[]): boolean {
  return (
    argv.length > 0 &&
    argv.length <= 64 &&
    /^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*$/.test(argv[0]) &&
    argv.every((arg) => !INVALID_RESUME_CHARACTER.test(arg)) &&
    argv.reduce((bytes, arg) => bytes + Buffer.byteLength(arg), 0) <= 8_192
  );
}

export function createHerdrReporter(env: NodeJS.ProcessEnv = process.env) {
  const binary = env.HERDR_BIN_PATH;
  const pane = env.HERDR_PANE_ID;
  if (env.HERDR_ENV !== "1" || !binary || !pane || !env.HERDR_SOCKET_PATH) {
    return { report(_report: HerdrReport) {}, async release() {} };
  }

  const childEnv = { ...env };
  let pending: HerdrReport | undefined;
  let active: Promise<void> | undefined;
  let releasePromise: Promise<void> | undefined;
  let lastSentKey: string | undefined;
  let reportStarted = false;
  let closing = false;
  let supportsResume = true;

  function run(args: string[]): Promise<number | null> {
    return new Promise((resolve) => {
      try {
        const child = spawn(binary as string, args, {
          env: childEnv,
          stdio: "ignore",
          windowsHide: true,
        });
        let settled = false;
        const finish = (code: number | null) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve(code);
        };
        const timer = setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            // Herdr must not delay exit if terminating its process fails.
          }
          child.unref();
          finish(null);
        }, REPORT_TIMEOUT_MS);
        child.once("spawn", () => {
          reportStarted = true;
        });
        child.once("error", () => finish(null));
        child.once("close", (code) => finish(code));
      } catch {
        // A missing binary or invalid environment must not interrupt Apex.
        resolve(null);
      }
    });
  }

  function argsFor(command: "report-agent" | "release-agent"): string[] {
    return [
      "pane",
      command,
      pane as string,
      "--source",
      SOURCE,
      "--agent",
      AGENT,
      "--seq",
      nextSequence(),
    ];
  }

  async function send(report: HerdrReport): Promise<number | null> {
    const args = argsFor("report-agent");
    args.push("--state", report.state);
    if (report.message && !report.message.includes("\0")) {
      args.push("--message", report.message);
    }
    const session = report.session;
    if (session?.id && !INVALID_RESUME_CHARACTER.test(session.id)) {
      args.push("--agent-session-id", session.id);
    }
    const withResume =
      supportsResume && session && validResumeArgv(session.resumeArgv);
    const code = await run(
      withResume ? [...args, "--", ...session.resumeArgv] : args,
    );
    if (code !== 2 || !withResume) return code;

    // Before 0.9.2 the CLI rejects the resume separator before reporting state.
    supportsResume = false;
    if (closing || pending) return code;
    return send(report);
  }

  function drain(): void {
    if (active || closing) return;
    active = (async () => {
      while (pending && !closing) {
        const report = pending;
        pending = undefined;
        const key = JSON.stringify(report);
        if (key === lastSentKey) continue;
        if ((await send(report)) === 0) lastSentKey = key;
      }
    })().finally(() => {
      active = undefined;
      if (pending && !closing) drain();
    });
  }

  return {
    report(report: HerdrReport): void {
      if (closing) return;
      pending = {
        state: report.state,
        message: report.message,
        session: report.session
          ? {
              id: report.session.id,
              resumeArgv: [...report.session.resumeArgv],
            }
          : undefined,
      };
      drain();
    },
    release(): Promise<void> {
      if (releasePromise) return releasePromise;
      closing = true;
      pending = undefined;
      releasePromise = (async () => {
        await active;
        if (reportStarted) await run(argsFor("release-agent"));
      })();
      return releasePromise;
    },
  };
}
