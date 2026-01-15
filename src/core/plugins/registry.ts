/**
 * Pensar Plugin System - Plugin Registry
 * 
 * Central registry for managing all loaded plugins. Provides methods for
 * registering, unregistering, and querying plugins by type.
 */

import type {
  Plugin,
  PluginEntry,
  PluginType,
  PluginSource,
  PluginStatus,
  ToolPlugin,
  AgentPlugin,
  ModelProviderPlugin,
  PromptPlugin,
  HookPlugin,
  HookEvent,
  HookHandler,
  ToolDefinition,
  AgentDefinition,
  ModelProviderDefinition,
  PromptDefinition,
  ToolPluginContext,
} from './types';

/**
 * Plugin registry event
 */
export type RegistryEvent = 
  | 'plugin:registered'
  | 'plugin:unregistered'
  | 'plugin:enabled'
  | 'plugin:disabled'
  | 'plugin:error';

/**
 * Registry event listener
 */
export type RegistryEventListener = (event: RegistryEvent, plugin: PluginEntry) => void;

/**
 * Plugin Registry
 * 
 * Manages all registered plugins and provides query methods.
 */
export class PluginRegistry {
  private plugins: Map<string, PluginEntry> = new Map();
  private listeners: Set<RegistryEventListener> = new Set();

  /**
   * Register a plugin
   */
  async register(
    plugin: Plugin,
    source: PluginSource = { type: 'builtin' }
  ): Promise<void> {
    const id = plugin.metadata.id;

    if (this.plugins.has(id)) {
      throw new Error(`Plugin with ID '${id}' is already registered`);
    }

    // Check dependencies
    if (plugin.metadata.dependencies) {
      for (const depId of plugin.metadata.dependencies) {
        if (!this.plugins.has(depId)) {
          throw new Error(
            `Plugin '${id}' requires dependency '${depId}' which is not registered`
          );
        }
      }
    }

    const entry: PluginEntry = {
      plugin,
      source,
      status: 'installed',
      loadedAt: new Date(),
    };

    // Call onLoad hook if present
    try {
      if (plugin.onLoad) {
        await plugin.onLoad();
      }
      entry.status = 'enabled';
    } catch (error: any) {
      entry.status = 'error';
      entry.error = error.message;
    }

    this.plugins.set(id, entry);
    this.emit('plugin:registered', entry);
  }

  /**
   * Unregister a plugin
   */
  async unregister(id: string): Promise<void> {
    const entry = this.plugins.get(id);
    if (!entry) {
      throw new Error(`Plugin '${id}' is not registered`);
    }

    // Check if other plugins depend on this one
    for (const [otherId, otherEntry] of this.plugins.entries()) {
      if (
        otherId !== id &&
        otherEntry.plugin.metadata.dependencies?.includes(id)
      ) {
        throw new Error(
          `Cannot unregister '${id}': plugin '${otherId}' depends on it`
        );
      }
    }

    // Call onUnload hook if present
    try {
      if (entry.plugin.onUnload) {
        await entry.plugin.onUnload();
      }
    } catch (error) {
      // Log but don't fail unregistration
      console.warn(`Error during plugin unload: ${error}`);
    }

    this.plugins.delete(id);
    this.emit('plugin:unregistered', entry);
  }

  /**
   * Enable a plugin
   */
  enable(id: string): void {
    const entry = this.plugins.get(id);
    if (!entry) {
      throw new Error(`Plugin '${id}' is not registered`);
    }
    entry.status = 'enabled';
    this.emit('plugin:enabled', entry);
  }

  /**
   * Disable a plugin
   */
  disable(id: string): void {
    const entry = this.plugins.get(id);
    if (!entry) {
      throw new Error(`Plugin '${id}' is not registered`);
    }
    entry.status = 'disabled';
    this.emit('plugin:disabled', entry);
  }

  /**
   * Get a plugin by ID
   */
  get(id: string): PluginEntry | undefined {
    return this.plugins.get(id);
  }

  /**
   * Check if a plugin is registered
   */
  has(id: string): boolean {
    return this.plugins.has(id);
  }

  /**
   * Get all registered plugins
   */
  getAll(): PluginEntry[] {
    return Array.from(this.plugins.values());
  }

  /**
   * Get all enabled plugins
   */
  getEnabled(): PluginEntry[] {
    return this.getAll().filter(e => e.status === 'enabled');
  }

  /**
   * Get plugins by type
   */
  getByType<T extends PluginType>(type: T): PluginEntry[] {
    return this.getEnabled().filter(e => e.plugin.type === type);
  }

  /**
   * Get all tool plugins
   */
  getToolPlugins(): ToolPlugin[] {
    return this.getByType('tool').map(e => e.plugin as ToolPlugin);
  }

  /**
   * Get all agent plugins
   */
  getAgentPlugins(): AgentPlugin[] {
    return this.getByType('agent').map(e => e.plugin as AgentPlugin);
  }

  /**
   * Get all model provider plugins
   */
  getModelProviderPlugins(): ModelProviderPlugin[] {
    return this.getByType('model-provider').map(e => e.plugin as ModelProviderPlugin);
  }

  /**
   * Get all prompt plugins
   */
  getPromptPlugins(): PromptPlugin[] {
    return this.getByType('prompt').map(e => e.plugin as PromptPlugin);
  }

  /**
   * Get all hook plugins
   */
  getHookPlugins(): HookPlugin[] {
    return this.getByType('hook').map(e => e.plugin as HookPlugin);
  }

  /**
   * Get aggregated tools from all tool plugins
   */
  getAllTools(): Record<string, { plugin: ToolPlugin; tool: ToolDefinition }> {
    const tools: Record<string, { plugin: ToolPlugin; tool: ToolDefinition }> = {};
    
    for (const plugin of this.getToolPlugins()) {
      for (const [name, tool] of Object.entries(plugin.tools)) {
        // Namespace tools by plugin ID to avoid conflicts
        const namespacedName = `${plugin.metadata.id}:${name}`;
        tools[namespacedName] = { plugin, tool };
        // Also store with simple name if no conflict
        if (!tools[name]) {
          tools[name] = { plugin, tool };
        }
      }
    }
    
    return tools;
  }

  /**
   * Get aggregated agents from all agent plugins
   */
  getAllAgents(): Record<string, { plugin: AgentPlugin; agent: AgentDefinition }> {
    const agents: Record<string, { plugin: AgentPlugin; agent: AgentDefinition }> = {};
    
    for (const plugin of this.getAgentPlugins()) {
      for (const [name, agent] of Object.entries(plugin.agents)) {
        const namespacedName = `${plugin.metadata.id}:${name}`;
        agents[namespacedName] = { plugin, agent };
        if (!agents[name]) {
          agents[name] = { plugin, agent };
        }
      }
    }
    
    return agents;
  }

  /**
   * Get aggregated model providers from all provider plugins
   */
  getAllModelProviders(): Record<string, { plugin: ModelProviderPlugin; provider: ModelProviderDefinition }> {
    const providers: Record<string, { plugin: ModelProviderPlugin; provider: ModelProviderDefinition }> = {};
    
    for (const plugin of this.getModelProviderPlugins()) {
      for (const [name, provider] of Object.entries(plugin.providers)) {
        const namespacedName = `${plugin.metadata.id}:${name}`;
        providers[namespacedName] = { plugin, provider };
        if (!providers[name]) {
          providers[name] = { plugin, provider };
        }
      }
    }
    
    return providers;
  }

  /**
   * Get aggregated prompts from all prompt plugins
   */
  getAllPrompts(): Record<string, { plugin: PromptPlugin; prompt: PromptDefinition }> {
    const prompts: Record<string, { plugin: PromptPlugin; prompt: PromptDefinition }> = {};
    
    for (const plugin of this.getPromptPlugins()) {
      for (const [name, prompt] of Object.entries(plugin.prompts)) {
        const namespacedName = `${plugin.metadata.id}:${name}`;
        prompts[namespacedName] = { plugin, prompt };
        if (!prompts[name]) {
          prompts[name] = { plugin, prompt };
        }
      }
    }
    
    return prompts;
  }

  /**
   * Execute hooks for an event
   */
  async executeHooks<T>(event: HookEvent, data: T): Promise<void> {
    const hookPlugins = this.getHookPlugins();
    
    for (const plugin of hookPlugins) {
      const handler = plugin.hooks[event];
      if (handler) {
        try {
          await handler(data);
        } catch (error) {
          console.error(
            `Error executing hook '${event}' from plugin '${plugin.metadata.id}':`,
            error
          );
        }
      }
    }
  }

  /**
   * Create a ToolSet from all registered tool plugins for use with AI SDK
   */
  createToolSet(context: ToolPluginContext): Record<string, any> {
    const toolSet: Record<string, any> = {};
    const allTools = this.getAllTools();
    
    for (const [name, { tool }] of Object.entries(allTools)) {
      // Create an AI SDK compatible tool
      toolSet[name] = {
        description: tool.description,
        parameters: tool.parameters,
        execute: async (params: any) => tool.execute(params, context),
      };
    }
    
    return toolSet;
  }

  /**
   * Add an event listener
   */
  addListener(listener: RegistryEventListener): void {
    this.listeners.add(listener);
  }

  /**
   * Remove an event listener
   */
  removeListener(listener: RegistryEventListener): void {
    this.listeners.delete(listener);
  }

  /**
   * Emit an event to all listeners
   */
  private emit(event: RegistryEvent, entry: PluginEntry): void {
    for (const listener of this.listeners) {
      try {
        listener(event, entry);
      } catch (error) {
        console.error(`Error in registry event listener:`, error);
      }
    }
  }

  /**
   * Clear all plugins (mainly for testing)
   */
  async clear(): Promise<void> {
    const ids = Array.from(this.plugins.keys());
    for (const id of ids) {
      await this.unregister(id);
    }
  }

  /**
   * Get registry statistics
   */
  getStats(): {
    total: number;
    byType: Record<PluginType, number>;
    byStatus: Record<PluginStatus, number>;
  } {
    const byType: Record<PluginType, number> = {
      tool: 0,
      agent: 0,
      'model-provider': 0,
      prompt: 0,
      hook: 0,
    };
    const byStatus: Record<PluginStatus, number> = {
      installed: 0,
      loaded: 0,
      enabled: 0,
      disabled: 0,
      error: 0,
    };

    for (const entry of this.plugins.values()) {
      byType[entry.plugin.type]++;
      byStatus[entry.status]++;
    }

    return {
      total: this.plugins.size,
      byType,
      byStatus,
    };
  }
}

// Global plugin registry instance
let globalRegistry: PluginRegistry | null = null;

/**
 * Get the global plugin registry instance
 */
export function getPluginRegistry(): PluginRegistry {
  if (!globalRegistry) {
    globalRegistry = new PluginRegistry();
  }
  return globalRegistry;
}

/**
 * Reset the global registry (for testing)
 */
export function resetPluginRegistry(): void {
  globalRegistry = null;
}
