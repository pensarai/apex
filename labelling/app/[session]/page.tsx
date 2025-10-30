import { getExecutionsDir } from "@/core/agent/sessions";
import { readdirSync, existsSync } from "fs";
import { join } from "path";
import Labelling from "./labelling";

function getMessagesFiles(session: string): string[] {
  const dir = getExecutionsDir();
  const sessionDir = join(dir, session);
  const messagesFiles: string[] = [];

  // Check for messages.json in the main session directory
  const files = readdirSync(sessionDir);
  const mainMessages = files.find((file) => file === "messages.json");
  if (mainMessages) {
    messagesFiles.push(join(sessionDir, mainMessages));
  }

  // Check for messages.json in subagents folders
  const subagentsDir = join(sessionDir, "subagents");
  if (existsSync(subagentsDir)) {
    const subagentFolders = readdirSync(subagentsDir);

    for (const agentId of subagentFolders) {
      const agentDir = join(subagentsDir, agentId);
      const agentFiles = readdirSync(agentDir);
      const agentMessages = agentFiles.find((file) => file === "messages.json");

      if (agentMessages) {
        messagesFiles.push(join(agentDir, agentMessages));
      }
    }
  }

  return messagesFiles;
}

export default async function SessionPage({
  params,
}: {
  params: Promise<{ session: string }>;
}) {
  const { session } = await params;

  const files = getMessagesFiles(session);

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <div className="text-2xl font-bold">{session}</div>
      <Labelling messagesFiles={files} />
    </div>
  );
}
