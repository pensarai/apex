import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

function sanitizeDirName(name: string): string {
  const cleaned = name.toLowerCase().replace(/[^a-z0-9-_.]/g, "_");
  return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned : "repo";
}

/**
 * Factory for the `clone_repository` tool.
 *
 * Clones a repository the owning workspace has connected into the agent's
 * sandbox so the generalized attack-surface agent can read source for a
 * discovered service. The tool is deliberately narrow: it will only clone a
 * repository present in `session.config.connectedRepositories`. An origin that
 * serves attacker-controlled content therefore cannot steer the agent into
 * cloning an arbitrary URL — the agent names a connected repo, never a URL.
 */
export function cloneRepository(ctx: ToolContext) {
  return tool({
    description: `Clone a repository that this workspace has connected, so you can read its source code.

Only repositories connected to the workspace can be cloned — you reference them by name, id, or connected URL, never by arbitrary URL. After cloning, use the code tools (read_file, list_files, grep, glob) against the returned path to confirm a service↔repo mapping and inform the application's threat model.

Returns the local path the repository was cloned to.`,
    inputSchema: z.object({
      repository: z
        .string()
        .describe(
          "The connected repository to clone, identified by its name, id, or connected clone URL.",
        ),
      ref: z
        .string()
        .optional()
        .describe(
          "Branch or ref to check out. Defaults to the repository's default branch.",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ repository, ref }) => {
      const connected = ctx.session.config?.connectedRepositories ?? [];
      if (connected.length === 0) {
        return {
          success: false,
          error: "no_connected_repositories",
          message:
            "This workspace has no connected repositories, so there is nothing to clone. Continue with blackbox discovery.",
        };
      }

      const needle = repository.trim().toLowerCase();
      const match = connected.find(
        (r) =>
          r.id.toLowerCase() === needle ||
          r.name.toLowerCase() === needle ||
          r.url.toLowerCase() === needle ||
          r.url.toLowerCase().replace(/\.git$/, "") ===
            needle.replace(/\.git$/, ""),
      );
      if (!match) {
        const available = connected.map((r) => r.name).join(", ");
        return {
          success: false,
          error: "repository_not_connected",
          message: `"${repository}" is not a connected repository. Connected repositories: ${available}. Only these can be cloned.`,
        };
      }

      const cloner = ctx.backends?.repoClone;
      if (!cloner) {
        return {
          success: false,
          error: "clone_unavailable",
          message:
            "Repository cloning is not available in this environment. Continue with blackbox discovery and web research.",
        };
      }

      const dest = `repos/${sanitizeDirName(match.name)}`;
      const result = await cloner.clone({
        repoUrl: match.url,
        ref: ref ?? match.defaultBranch,
        dest,
      });
      if (!result.success) {
        return {
          success: false,
          error: "clone_failed",
          message: `Failed to clone "${match.name}": ${result.error ?? "unknown error"}`,
        };
      }

      return {
        success: true,
        repository: match.name,
        repositoryId: match.id,
        path: result.path,
        message: `Cloned "${match.name}" to ${result.path}. Use the code tools against this path.`,
      };
    },
  });
}
