// Plugin system — public API
export { PluginRegistry, getPluginRegistry, resetPluginRegistry } from "./registry";
export { buildPluginPromptSection } from "./context";
export { loadBuiltinPlugins } from "./loader";

export type {
  PluginManifest,
  PluginPhase,
  LoadedPlugin,
  ResolvedContextFile,
} from "./types";

export { PluginManifestSchema, PluginPhaseSchema } from "./types";
