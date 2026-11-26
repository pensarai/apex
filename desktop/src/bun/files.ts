import { stat } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { sessions } from "../../../src/core/session";
import { fileReference } from "../file-reference";
import { sessionId } from "./workspace";

export function createFileRequests(options: {
  cwd: () => string;
  openPath: (path: string) => boolean;
  requireAcceptance: () => void;
}) {
  return {
    async openLocalFile(input: { path: string; sessionId?: string }) {
      options.requireAcceptance();
      const file = fileReference(input.path);
      if (!file) throw new Error("This is not a local file path.");
      const session = input.sessionId
        ? await sessions.get(sessionId(input.sessionId))
        : undefined;
      const path = file.path.startsWith("~/")
        ? resolve(homedir(), file.path.slice(2))
        : file.path;
      const candidates = isAbsolute(path)
        ? [path]
        : [
            ...new Set(
              [
                session?.rootPath,
                session?.config?.agentCwd,
                options.cwd(),
              ].filter((root): root is string => !!root),
            ),
          ].map((root) => resolve(root, path));
      for (const candidate of candidates) {
        try {
          if (!(await stat(candidate)).isFile()) continue;
        } catch (error) {
          if (
            ["ENOENT", "ENOTDIR"].includes(
              (error as NodeJS.ErrnoException).code ?? "",
            )
          )
            continue;
          throw error;
        }
        if (!options.openPath(candidate))
          throw new Error(`Could not open ${file.name}.`);
        return;
      }
      throw new Error(`File not found: ${file.path}`);
    },
  };
}
