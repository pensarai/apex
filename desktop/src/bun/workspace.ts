import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { FindingsRegistry } from "../../../src/core/findings/registry";
import { REPORT_FILENAME_MD } from "../../../src/core/report";
import type { WorkerExecutable } from "../../../src/core/runtime/launchLocalWorker";
import { openRecordedRunClient } from "../../../src/core/runtime/recordedRunClient";
import { list, sessions } from "../../../src/core/session";
import type { RunAction, RunDetail, SessionRow } from "../shared";

export function sessionId(id: string): string {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(id))
    throw new Error("Invalid session ID");
  return id;
}

export async function sessionRows(): Promise<SessionRow[]> {
  const rows: SessionRow[] = [];
  for await (const session of list()) {
    rows.push({
      id: session.id,
      name: session.name || session.id,
      targets: session.targets,
      updated: session.time.updated,
      created: session.time.created,
    });
  }
  return rows.sort((a, b) => b.updated - a.updated);
}

async function readReport(root: string) {
  try {
    return await readFile(join(root, REPORT_FILENAME_MD), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

export async function sessionArtifacts(id: string) {
  const session = await sessions.get(sessionId(id));
  const findings = FindingsRegistry.fromDirectory(
    session.findingsPath,
  ).getFindings();
  return {
    report: await readReport(session.rootPath),
    findings: findings.map(
      ({
        title,
        severity,
        endpoint,
        description,
        impact,
        evidence,
        remediation,
      }) => ({
        title,
        severity,
        endpoint,
        description,
        impact,
        evidence,
        remediation,
      }),
    ),
  };
}

export async function openRuns(
  executable: WorkerExecutable,
  databasePath?: string,
) {
  const client = await openRecordedRunClient(databasePath);
  return {
    close: () => client.close(),
    async list() {
      return (await client.list()).map(({ spec, status, updatedAt }) => ({
        id: spec.runId,
        target: spec.target,
        prompt: spec.prompt,
        model: spec.model,
        status,
        updated: updatedAt,
      }));
    },
    async *watch(id: string, signal: AbortSignal): AsyncGenerator<RunDetail> {
      for await (const {
        connection,
        observation,
        worker,
        error,
      } of client.watch(id, signal)) {
        const { record, control, approvals, context } = observation;
        yield {
          connection,
          error:
            error ??
            (worker?.error &&
              [worker.error.message, ...(worker.error.blockers ?? [])].join(
                "\n",
              )),
          status: record?.status,
          attempt: record?.attemptId,
          control:
            (control && {
              revision: control.revision,
              intent: control.intent,
            }) ||
            undefined,
          approvals: approvals
            .filter((a) => a.state === "pending")
            .map((a) => ({
              id: a.approvalId,
              tool: a.toolName,
              input: JSON.stringify(a.input, null, 2),
            })),
          transcript: (context?.messages ?? []).map((message, index) => ({
            id: `${context?.epoch}-${index}`,
            role: message.role,
            text:
              typeof message.content === "string"
                ? message.content
                : message.content
                    .map((part) =>
                      part.type === "text"
                        ? part.text
                        : part.type === "tool-call"
                          ? `${part.toolName} ${JSON.stringify(part.input)}`
                          : part.type === "tool-result"
                            ? `${part.toolName} ${JSON.stringify(part.output)}`
                            : `[${part.type}]`,
                    )
                    .join("\n"),
          })),
        };
      }
    },
    async start(spec: string) {
      const result = await client.start(JSON.parse(spec), executable);
      return result.snapshot.runId;
    },
    async act(id: string, action: RunAction) {
      switch (action.type) {
        case "pause":
        case "stop":
          await client.requestControl(id, action.type, action.revision);
          break;
        case "resume":
          await client.resume(id, action.attempt, executable);
          break;
        case "approved":
        case "denied":
          await client.resolveApproval(id, action.approvalId, action.type);
          break;
        default:
          throw new Error("Unknown run action");
      }
    },
  };
}
