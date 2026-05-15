import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "fs";
import { join } from "path";
import type { AgentEventBus, ExecutionEventHandler } from "../eventBus";
import type { AgentExecutionEvent, DurableAgentEvent } from "./events";
import type { ExecutionSession } from "./sessions";
import type { AgentNode } from "./nodes";
import type { Message } from "./messages";
import type { Part } from "./parts";

const SESSION_FILE = "session.json";
const EVENTS_FILE = "events.jsonl";
const NODES_FILE = "nodes.jsonl";
const MESSAGES_FILE = "messages.jsonl";
const PARTS_FILE = "parts.jsonl";

export interface FileStorageOptions {
  bus: AgentEventBus;
  rootDir: string;
  session: ExecutionSession;
}

export interface ExecutionFileStorage {
  detach(): void;
  flush(): void;
  readonly path: string;
}

export function attachExecutionFileStorage(
  opts: FileStorageOptions,
): ExecutionFileStorage {
  const sessionDir = join(opts.rootDir, opts.session.id);
  mkdirSync(sessionDir, { recursive: true });

  writeFileSync(
    join(sessionDir, SESSION_FILE),
    JSON.stringify(opts.session, null, 2),
  );

  const eventsPath = join(sessionDir, EVENTS_FILE);
  const nodesPath = join(sessionDir, NODES_FILE);
  const messagesPath = join(sessionDir, MESSAGES_FILE);
  const partsPath = join(sessionDir, PARTS_FILE);

  const handler: ExecutionEventHandler = (event) => {
    if (event.channel !== "durable") return;
    appendFileSync(eventsPath, JSON.stringify(event) + "\n");
    projectDurableEvent(event, {
      nodesPath,
      messagesPath,
      partsPath,
    });
  };

  opts.bus.onExecution(handler);

  return {
    detach() {
      opts.bus.offExecution(handler);
    },
    flush() {
      // appendFileSync is synchronous; nothing to flush.
    },
    path: sessionDir,
  };
}

function projectDurableEvent(
  event: DurableAgentEvent,
  paths: { nodesPath: string; messagesPath: string; partsPath: string },
): void {
  switch (event.type) {
    case "node.created":
      appendFileSync(paths.nodesPath, JSON.stringify(event.node) + "\n");
      break;

    case "node.state_changed":
    case "node.completed":
      appendFileSync(
        paths.nodesPath,
        JSON.stringify({
          op: event.type,
          nodeId: event.nodeId,
          ...(event.type === "node.state_changed"
            ? { state: event.state, reason: event.reason }
            : { result: event.result, errorMessage: event.errorMessage }),
          timestamp: event.timestamp,
        }) + "\n",
      );
      break;

    case "message.created":
      appendFileSync(
        paths.messagesPath,
        JSON.stringify(event.message) + "\n",
      );
      for (const part of event.parts) {
        appendFileSync(paths.partsPath, JSON.stringify(part) + "\n");
      }
      break;

    case "part.added":
      appendFileSync(paths.partsPath, JSON.stringify(event.part) + "\n");
      break;

    case "part.updated":
      appendFileSync(
        paths.partsPath,
        JSON.stringify({
          op: "part.updated",
          partId: event.partId,
          messageId: event.messageId,
          patch: event.patch,
          timestamp: event.timestamp,
        }) + "\n",
      );
      break;

    case "step.finished":
    case "usage.recorded":
      break;
  }
}

export interface LoadedSession {
  session: ExecutionSession;
  events: AgentExecutionEvent[];
  nodes: AgentNode[];
  messages: Message[];
  parts: Part[];
}

export function loadSessionFromDisk(
  rootDir: string,
  sessionId: string,
): LoadedSession | null {
  const sessionDir = join(rootDir, sessionId);
  const sessionFile = join(sessionDir, SESSION_FILE);
  if (!existsSync(sessionFile)) return null;

  const session = JSON.parse(
    readFileSync(sessionFile, "utf8"),
  ) as ExecutionSession;
  const events = readJsonl<AgentExecutionEvent>(join(sessionDir, EVENTS_FILE));
  const nodes = readJsonl<AgentNode>(join(sessionDir, NODES_FILE)).filter(
    (n): n is AgentNode => typeof (n as AgentNode).kind === "string",
  );
  const messages = readJsonl<Message>(join(sessionDir, MESSAGES_FILE)).filter(
    (m): m is Message => typeof (m as Message).role === "string",
  );
  const parts = readJsonl<Part>(join(sessionDir, PARTS_FILE)).filter(
    (p): p is Part => typeof (p as Part).type === "string",
  );

  return { session, events, nodes, messages, parts };
}

function readJsonl<T>(path: string): T[] {
  if (!existsSync(path)) return [];
  const text = readFileSync(path, "utf8");
  if (!text.trim()) return [];
  return text
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as T);
}
