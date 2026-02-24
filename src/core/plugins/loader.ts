import { readdirSync, readFileSync, existsSync, statSync } from "fs";
import { execSync } from "child_process";
import { join, resolve } from "path";
import { PluginManifestSchema } from "./types";
import type { LoadedPlugin, PluginManifest, ResolvedContextFile } from "./types";

const BUILTIN_DIR = resolve(__dirname, "builtin");

/**
 * Check if a binary is available on $PATH.
 */
function isBinaryInstalled(binary: string): boolean {
  try {
    execSync(`which ${binary}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Check all plugin dependencies. Returns list of missing dependency descriptions.
 */
function checkDependencies(
  manifest: PluginManifest,
): string[] {
  const missing: string[] = [];

  for (const dep of manifest.requires) {
    if (dep.binary && !isBinaryInstalled(dep.binary)) {
      const hint = dep.installHint
        ? `${dep.binary} (${dep.installHint})`
        : dep.binary;
      missing.push(hint);
    }
  }

  return missing;
}

/**
 * Load all builtin plugins from src/core/plugins/builtin/.
 *
 * Scans for subdirectories containing a manifest.json, validates each
 * manifest against the Zod schema, checks CLI dependencies, and returns
 * LoadedPlugin instances. Plugins with missing dependencies are skipped.
 */
export function loadBuiltinPlugins(): LoadedPlugin[] {
  if (!existsSync(BUILTIN_DIR)) {
    return [];
  }

  const entries = readdirSync(BUILTIN_DIR, { withFileTypes: true });
  const plugins: LoadedPlugin[] = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;

    const pluginDir = join(BUILTIN_DIR, entry.name);
    const manifestPath = join(pluginDir, "manifest.json");

    if (!existsSync(manifestPath)) {
      continue;
    }

    try {
      const raw = readFileSync(manifestPath, "utf-8");
      const json = JSON.parse(raw);
      const parsed = PluginManifestSchema.safeParse(json);

      if (!parsed.success) {
        console.warn(
          `[plugins] Invalid manifest in ${entry.name}:`,
          parsed.error.format(),
        );
        continue;
      }

      const manifest = parsed.data;

      // Check CLI dependencies
      const missingDeps = checkDependencies(manifest);
      if (missingDeps.length > 0) {
        console.warn(
          `[plugins] Skipping ${manifest.displayName}: missing dependencies: ${missingDeps.join(", ")}`,
        );
        continue;
      }

      // Resolve context file paths (don't read into memory — agents read on demand)
      const contextFiles: ResolvedContextFile[] = [];
      for (const ctx of manifest.provides.context) {
        const absPath = join(pluginDir, ctx.file);
        if (existsSync(absPath) && statSync(absPath).isFile()) {
          contextFiles.push({
            absolutePath: absPath,
            description: ctx.description ?? "",
            phases: ctx.phases,
            priority: ctx.priority,
          });
        } else {
          console.warn(
            `[plugins] Context file not found: ${ctx.file} in ${entry.name}`,
          );
        }
      }

      plugins.push({
        manifest,
        basePath: pluginDir,
        enabled: true,
        contextFiles,
      });
    } catch (err) {
      console.warn(
        `[plugins] Failed to load plugin from ${entry.name}:`,
        err instanceof Error ? err.message : err,
      );
    }
  }

  return plugins;
}
