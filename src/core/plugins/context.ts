import type { LoadedPlugin, PluginPhase } from "./types";

/**
 * Build a prompt section that summarizes active plugins for injection
 * into agent system prompts.
 *
 * Context .md files are NOT injected directly — instead the prompt
 * contains pointers so agents can read them on-demand via read_file.
 * This keeps system prompts compact.
 */
export function buildPluginPromptSection(
  plugins: LoadedPlugin[],
  phase: PluginPhase,
): string {
  const sections: string[] = [];

  for (const plugin of plugins) {
    // Filter context files by phase
    const relevantContext = plugin.contextFiles.filter(
      (c) => c.phases.includes(phase) || c.phases.includes("all"),
    );

    if (relevantContext.length === 0) continue;

    // Sort by priority (higher first)
    relevantContext.sort((a, b) => b.priority - a.priority);

    const lines: string[] = [];
    lines.push(`## ${plugin.manifest.displayName}`);
    lines.push(plugin.manifest.description);

    for (const ctx of relevantContext) {
      lines.push(`Context file: ${ctx.absolutePath}`);
      if (ctx.description) {
        lines.push(`  → ${ctx.description}`);
      }
      lines.push(
        `  → Use read_file to load this when testing targets on this platform.`,
      );
    }

    sections.push(lines.join("\n"));
  }

  if (sections.length === 0) return "";

  return "\n\n# Platform Plugins\n\n" + sections.join("\n\n");
}
