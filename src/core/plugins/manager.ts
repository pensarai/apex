/**
 * Pensar Plugin System - Plugin Manager
 * 
 * High-level API for managing plugins, including installation,
 * configuration, and integration with the core system.
 */

import { existsSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { join } from 'path';
import os from 'os';
import type {
  Plugin,
  PluginType,
  PluginEntry,
  ToolPlugin,
  AgentPlugin,
  ModelProviderPlugin,
  PromptPlugin,
  HookPlugin,
  HookEvent,
  ToolPluginContext,
  AgentPluginContext,
  AgentInput,
  AgentResult,
  ModelProviderConfig,
} from './types';
import {
  PluginRegistry,
  getPluginRegistry,
  type RegistryEvent,
  type RegistryEventListener,
} from './registry';
import {
  loadFromPath,
  loadFromNpm,
  loadPluginsFromDirectory,
  loadPluginsFromConfig,
  discoverPlugins,
  getPluginsDir,
  type PluginLoaderConfig,
} from './loader';
import type { AIModel, ModelInfo } from '../ai';
import type { Session } from '../session';

/**
 * Plugin manager options
 */
export interface PluginManagerOptions {
  /** Custom registry instance */
  registry?: PluginRegistry;
  /** Plugin configuration */
  config?: PluginLoaderConfig;
  /** Auto-load plugins on initialization */
  autoLoad?: boolean;
}

/**
 * Plugin installation options
 */
export interface InstallPluginOptions {
  /** Source: 'local' | 'npm' | 'url' */
  source: 'local' | 'npm' | 'url';
  /** Path, package name, or URL */
  location: string;
  /** Version (for npm) */
  version?: string;
  /** Enable after installation */
  enable?: boolean;
}

/**
 * Plugin Manager
 * 
 * Provides a unified interface for all plugin operations.
 */
export class PluginManager {
  private registry: PluginRegistry;
  private config: PluginLoaderConfig;
  private initialized: boolean = false;
  private configPath: string;

  constructor(options: PluginManagerOptions = {}) {
    this.registry = options.registry || getPluginRegistry();
    this.config = options.config || {};
    this.configPath = join(os.homedir(), '.pensar', 'plugins.json');

    // Load saved configuration
    this.loadConfig();
  }

  /**
   * Initialize the plugin system
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    // Ensure plugins directory exists
    const pluginsDir = getPluginsDir();
    if (!existsSync(pluginsDir)) {
      mkdirSync(pluginsDir, { recursive: true });
    }

    // Load plugins from config
    await loadPluginsFromConfig(this.config, { registry: this.registry });

    this.initialized = true;
  }

  /**
   * Load configuration from disk
   */
  private loadConfig(): void {
    if (existsSync(this.configPath)) {
      try {
        const data = readFileSync(this.configPath, 'utf-8');
        this.config = JSON.parse(data);
      } catch {
        // Use default config
      }
    }
  }

  /**
   * Save configuration to disk
   */
  private saveConfig(): void {
    const dir = join(os.homedir(), '.pensar');
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(this.configPath, JSON.stringify(this.config, null, 2));
  }

  /**
   * Install a plugin
   */
  async install(options: InstallPluginOptions): Promise<Plugin> {
    let plugin: Plugin;

    switch (options.source) {
      case 'local':
        plugin = await loadFromPath(options.location, { registry: this.registry });
        // Add to config for persistence
        if (!this.config.paths) {
          this.config.paths = [];
        }
        if (!this.config.paths.includes(options.location)) {
          this.config.paths.push(options.location);
        }
        break;

      case 'npm':
        plugin = await loadFromNpm(options.location, options.version, { registry: this.registry });
        // Add to config for persistence
        if (!this.config.packages) {
          this.config.packages = [];
        }
        const pkgSpec = options.version ? `${options.location}@${options.version}` : options.location;
        if (!this.config.packages.includes(pkgSpec)) {
          this.config.packages.push(pkgSpec);
        }
        break;

      case 'url':
        throw new Error('URL installation not yet implemented');

      default:
        throw new Error(`Unknown source type: ${options.source}`);
    }

    // Enable by default unless specified otherwise
    if (options.enable !== false) {
      this.registry.enable(plugin.metadata.id);
    }

    this.saveConfig();
    return plugin;
  }

  /**
   * Uninstall a plugin
   */
  async uninstall(pluginId: string): Promise<void> {
    const entry = this.registry.get(pluginId);
    if (!entry) {
      throw new Error(`Plugin '${pluginId}' is not installed`);
    }

    // Remove from registry
    await this.registry.unregister(pluginId);

    // Remove from config
    if (entry.source.type === 'local' && this.config.paths) {
      this.config.paths = this.config.paths.filter(p => p !== entry.source.path);
    }
    if (entry.source.type === 'npm' && this.config.packages) {
      this.config.packages = this.config.packages.filter(
        p => !p.startsWith((entry.source as any).package)
      );
    }

    this.saveConfig();
  }

  /**
   * Enable a plugin
   */
  enable(pluginId: string): void {
    this.registry.enable(pluginId);

    // Update config
    if (this.config.disabled) {
      this.config.disabled = this.config.disabled.filter(id => id !== pluginId);
      this.saveConfig();
    }
  }

  /**
   * Disable a plugin
   */
  disable(pluginId: string): void {
    this.registry.disable(pluginId);

    // Update config
    if (!this.config.disabled) {
      this.config.disabled = [];
    }
    if (!this.config.disabled.includes(pluginId)) {
      this.config.disabled.push(pluginId);
      this.saveConfig();
    }
  }

  /**
   * Get all installed plugins
   */
  list(): PluginEntry[] {
    return this.registry.getAll();
  }

  /**
   * Get a specific plugin
   */
  get(pluginId: string): PluginEntry | undefined {
    return this.registry.get(pluginId);
  }

  /**
   * Check if a plugin is installed
   */
  isInstalled(pluginId: string): boolean {
    return this.registry.has(pluginId);
  }

  /**
   * Discover available plugins (not yet installed)
   */
  async discover(): Promise<Array<{ path: string; manifest?: any }>> {
    return discoverPlugins();
  }

  // =========================================================================
  // Tool Integration
  // =========================================================================

  /**
   * Get all available tools from plugins
   */
  getTools(): Record<string, { plugin: ToolPlugin; tool: any }> {
    return this.registry.getAllTools();
  }

  /**
   * Create a ToolSet for AI SDK from all plugin tools
   */
  createToolSet(context: ToolPluginContext): Record<string, any> {
    return this.registry.createToolSet(context);
  }

  // =========================================================================
  // Agent Integration
  // =========================================================================

  /**
   * Get all available agents from plugins
   */
  getAgents(): Record<string, { plugin: AgentPlugin; agent: any }> {
    return this.registry.getAllAgents();
  }

  /**
   * Run a plugin agent
   */
  async runAgent(
    agentName: string,
    input: AgentInput,
    context: AgentPluginContext
  ): Promise<AgentResult> {
    const agents = this.registry.getAllAgents();
    const agentEntry = agents[agentName];

    if (!agentEntry) {
      throw new Error(`Agent '${agentName}' not found`);
    }

    // Execute hooks
    await this.registry.executeHooks('agent:start', { agent: agentName, input });

    try {
      const result = await agentEntry.agent.execute(input, context);
      await this.registry.executeHooks('agent:end', { agent: agentName, input, result });
      return result;
    } catch (error: any) {
      await this.registry.executeHooks('agent:end', { agent: agentName, input, error });
      throw error;
    }
  }

  // =========================================================================
  // Model Provider Integration
  // =========================================================================

  /**
   * Get all available model providers from plugins
   */
  getModelProviders(): Record<string, { plugin: ModelProviderPlugin; provider: any }> {
    return this.registry.getAllModelProviders();
  }

  /**
   * Get all available models from all providers
   */
  getAllModels(): ModelInfo[] {
    const models: ModelInfo[] = [];
    const providers = this.registry.getAllModelProviders();

    for (const { provider } of Object.values(providers)) {
      models.push(...provider.models);
    }

    return models;
  }

  /**
   * Create a model provider instance
   */
  createModelProvider(providerName: string, config: ModelProviderConfig): any {
    const providers = this.registry.getAllModelProviders();
    const providerEntry = providers[providerName];

    if (!providerEntry) {
      throw new Error(`Model provider '${providerName}' not found`);
    }

    // Validate config if validator exists
    if (providerEntry.provider.validateConfig) {
      const validation = providerEntry.provider.validateConfig(config);
      if (!validation.valid) {
        throw new Error(`Invalid provider config: ${validation.error}`);
      }
    }

    return providerEntry.provider.createProvider(config);
  }

  // =========================================================================
  // Prompt Integration
  // =========================================================================

  /**
   * Get all available prompts from plugins
   */
  getPrompts(): Record<string, { plugin: PromptPlugin; prompt: any }> {
    return this.registry.getAllPrompts();
  }

  /**
   * Get a specific prompt
   */
  getPrompt(promptName: string): any | undefined {
    const prompts = this.registry.getAllPrompts();
    return prompts[promptName]?.prompt;
  }

  // =========================================================================
  // Hook Integration
  // =========================================================================

  /**
   * Execute hooks for an event
   */
  async executeHooks<T>(event: HookEvent, data: T): Promise<void> {
    await this.registry.executeHooks(event, data);
  }

  // =========================================================================
  // Event Handling
  // =========================================================================

  /**
   * Add a registry event listener
   */
  onPluginEvent(listener: RegistryEventListener): void {
    this.registry.addListener(listener);
  }

  /**
   * Remove a registry event listener
   */
  offPluginEvent(listener: RegistryEventListener): void {
    this.registry.removeListener(listener);
  }

  // =========================================================================
  // Statistics
  // =========================================================================

  /**
   * Get plugin system statistics
   */
  getStats() {
    return this.registry.getStats();
  }
}

// Global plugin manager instance
let globalManager: PluginManager | null = null;

/**
 * Get the global plugin manager instance
 */
export function getPluginManager(): PluginManager {
  if (!globalManager) {
    globalManager = new PluginManager();
  }
  return globalManager;
}

/**
 * Initialize the global plugin manager
 */
export async function initializePlugins(): Promise<PluginManager> {
  const manager = getPluginManager();
  await manager.initialize();
  return manager;
}

/**
 * Reset the global plugin manager (for testing)
 */
export function resetPluginManager(): void {
  globalManager = null;
}
