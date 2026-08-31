/**
 * How this client identifies itself to the Pensar Console API.
 *
 * The API is reachable by the CLI, CI jobs, curl and customer automation with
 * the same credentials, and the credential says nothing about the client. So we
 * say who we are on every request; a caller that says nothing is recorded as a
 * generic API caller rather than being assumed to be the CLI.
 *
 * Console parses these in `packages/functions/src/callerClient.ts` and only
 * honours a known client name and a bounded command, so keep the names in step
 * and keep the command a short identifier, never free text.
 */
import { getCurrentVersion } from "../installation";

export const CLIENT_HEADERS = {
  client: "X-Pensar-Client",
  version: "X-Pensar-Client-Version",
  command: "X-Pensar-Command",
} as const;

/** What this binary is, from Console's point of view. */
const CLIENT_NAME = "cli";

// The top-level command, set once by the CLI router. Deliberately not the
// subcommand: Console already records the endpoint each request hits, so
// `pentests` here plus `POST /pentests` there gives the same resolution
// without threading a name through every API function.
let currentCommand: string | undefined;

/** Record the command being run. Called once, by the CLI entrypoint. */
export function setCurrentCommand(command: string | undefined): void {
  currentCommand = normalizeCommand(command);
}

export function getCurrentCommand(): string | undefined {
  return currentCommand;
}

// Console drops anything that is not a short lowercase identifier, so send
// nothing rather than something it will discard.
const COMMAND_SHAPE = /^[a-z][a-z0-9-]{0,31}$/;

function normalizeCommand(command: string | undefined): string | undefined {
  if (!command) return undefined;
  const trimmed = command.trim().toLowerCase();
  return COMMAND_SHAPE.test(trimmed) ? trimmed : undefined;
}

/** Client identification headers for a Console API request. */
export function clientIdentityHeaders(): Record<string, string> {
  const command = getCurrentCommand();
  return {
    [CLIENT_HEADERS.client]: CLIENT_NAME,
    [CLIENT_HEADERS.version]: getCurrentVersion(),
    ...(command ? { [CLIENT_HEADERS.command]: command } : {}),
  };
}
