import type { LoadedPlugin, PluginPhase } from "./types";
import { loadBuiltinPlugins } from "./loader";
import { buildPluginPromptSection } from "./context";

/**
 * Central registry for all loaded plugins.
 *
 * Plugins are context-only: they inject domain-specific knowledge into
 * agent system prompts so agents know how to use existing tools
 * (execute_command, http_request) to query platform APIs.
 */
export class PluginRegistry {
  private plugins: LoadedPlugin[] = [];
  private initialized = false;

  /**
   * Load all builtin plugins.
   * Safe to call multiple times — subsequent calls are no-ops.
   */
  initialize(): void {
    if (this.initialized) return;
    this.initialized = true;
    this.plugins = loadBuiltinPlugins();
  }

  /** Returns all enabled plugins. */
  getActivePlugins(): LoadedPlugin[] {
    return this.plugins.filter((p) => p.enabled);
  }

  /** Returns all loaded plugins regardless of state. */
  getAllPlugins(): LoadedPlugin[] {
    return [...this.plugins];
  }

  /** Build the prompt section for active plugins matching the given phase. */
  getContextForPhase(phase: PluginPhase): string {
    return buildPluginPromptSection(this.getActivePlugins(), phase);
  }
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

let _instance: PluginRegistry | null = null;

export function getPluginRegistry(): PluginRegistry {
  if (!_instance) {
    _instance = new PluginRegistry();
    _instance.initialize();
  }
  return _instance;
}

/** Reset the singleton (primarily for testing). */
export function resetPluginRegistry(): void {
  _instance = null;
}
