import {
  ALL_TOOL_NAMES,
  SKILL_TOOL_NAMES,
} from "../../../src/core/agents/offSecAgent";
import { type SessionInfo, sessions } from "../../../src/core/session";
import { sessionId } from "../bun/workspace";

const catalog = [
  ...new Set<string>([...ALL_TOOL_NAMES, ...SKILL_TOOL_NAMES]),
].sort();
export function selectedTools(
  session: SessionInfo | undefined,
  allowed: readonly string[],
): string[] {
  const choices = session?.config?.toolsetState?.enabledTools;
  return allowed.filter((name) => choices?.[name] !== false);
}

export const toolRequests = {
  async toolSelection({ id }: { id: string }) {
    const session = await sessions.get(sessionId(id));
    const enabled = new Set(selectedTools(session, catalog));
    return catalog.map((name) => ({ name, enabled: enabled.has(name) }));
  },
  async setToolEnabled({
    id,
    name,
    enabled,
  }: {
    id: string;
    name: string;
    enabled: boolean;
  }) {
    if (!catalog.includes(name) || typeof enabled !== "boolean")
      throw new Error("Invalid tool selection.");
    await sessions.toggleTool(sessionId(id), name, enabled);
  },
};
