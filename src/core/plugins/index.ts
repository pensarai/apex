/**
 * Pensar Plugin System
 * 
 * A modular plugin architecture for extending Pensar's capabilities.
 * 
 * Plugin Types:
 * - Tool Plugins: Add custom security testing tools
 * - Agent Plugins: Add custom agents for specific testing scenarios
 * - Model Provider Plugins: Add custom AI model providers
 * - Prompt Plugins: Add custom vulnerability prompts and techniques
 * - Hook Plugins: Add lifecycle hooks for events
 * 
 * @example
 * ```typescript
 * import { getPluginManager, createToolPlugin } from '@pensar/apex/plugins';
 * 
 * // Create a custom tool plugin
 * const myPlugin = createToolPlugin({
 *   metadata: {
 *     id: 'my-tool-plugin',
 *     name: 'My Tool Plugin',
 *     version: '1.0.0',
 *     description: 'A custom tool plugin',
 *   },
 *   tools: {
 *     my_tool: {
 *       description: 'Does something useful',
 *       parameters: z.object({ input: z.string() }),
 *       execute: async (params) => ({ result: params.input.toUpperCase() }),
 *     },
 *   },
 * });
 * 
 * // Install the plugin
 * const manager = getPluginManager();
 * await manager.install({ source: 'local', location: './my-plugin' });
 * ```
 */

// Types
export type {
  // Base types
  PluginType,
  PluginMetadata,
  BasePlugin,
  Plugin,
  PluginManifest,
  PluginSource,
  PluginStatus,
  PluginEntry,
  
  // Tool plugin types
  ToolPluginContext,
  ToolDefinition,
  ToolPlugin,
  
  // Agent plugin types
  AgentPluginContext,
  AgentInput,
  AgentResult,
  AgentDefinition,
  AgentPlugin,
  
  // Model provider types
  ModelProviderConfig,
  ModelProviderDefinition,
  ModelProviderPlugin,
  
  // Prompt plugin types
  PromptTemplateContext,
  PromptDefinition,
  PromptPlugin,
  
  // Hook plugin types
  HookEvent,
  HookHandler,
  HookPlugin,
} from './types';

// Registry
export {
  PluginRegistry,
  getPluginRegistry,
  resetPluginRegistry,
  type RegistryEvent,
  type RegistryEventListener,
} from './registry';

// Loader
export {
  loadFromPath,
  loadFromNpm,
  loadPluginsFromDirectory,
  loadPluginsFromConfig,
  discoverPlugins,
  getPluginsDir,
  type LoadPluginOptions,
  type DiscoveredPlugin,
  type PluginLoaderConfig,
} from './loader';

// Manager
export {
  PluginManager,
  getPluginManager,
  initializePlugins,
  resetPluginManager,
  type PluginManagerOptions,
  type InstallPluginOptions,
} from './manager';

// Plugin creation helpers
export {
  createToolPlugin,
  createAgentPlugin,
  createModelProviderPlugin,
  createPromptPlugin,
  createHookPlugin,
} from './helpers';

// Integration utilities
export {
  createToolContext,
  convertPluginTool,
  getPluginToolSet,
  mergeToolSets,
  createAgentContext,
  getAllAvailableModels,
  executePluginHooks,
  isPluginModel,
  getPluginModelProvider,
} from './integration';
