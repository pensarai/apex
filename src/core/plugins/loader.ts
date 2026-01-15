/**
 * Pensar Plugin System - Plugin Loader
 * 
 * Handles loading plugins from various sources:
 * - Built-in plugins
 * - Local file system paths
 * - NPM packages
 * - Remote URLs
 */

import { existsSync, readFileSync, readdirSync } from 'fs';
import { join, resolve, dirname, basename } from 'path';
import os from 'os';
import type {
  Plugin,
  PluginManifest,
  PluginSource,
  PluginType,
} from './types';
import { getPluginRegistry, type PluginRegistry } from './registry';

/**
 * Options for plugin loading
 */
export interface LoadPluginOptions {
  /** Skip validation */
  skipValidation?: boolean;
  /** Custom registry to use */
  registry?: PluginRegistry;
}

/**
 * Plugin discovery result
 */
export interface DiscoveredPlugin {
  /** Path or identifier */
  path: string;
  /** Plugin manifest if found */
  manifest?: PluginManifest;
  /** Source type */
  source: PluginSource;
}

/**
 * Validate plugin structure
 */
function validatePlugin(plugin: any): plugin is Plugin {
  if (!plugin) {
    throw new Error('Plugin is null or undefined');
  }

  if (!plugin.type) {
    throw new Error('Plugin missing required "type" property');
  }

  const validTypes: PluginType[] = ['tool', 'agent', 'model-provider', 'prompt', 'hook'];
  if (!validTypes.includes(plugin.type)) {
    throw new Error(`Invalid plugin type: ${plugin.type}`);
  }

  if (!plugin.metadata) {
    throw new Error('Plugin missing required "metadata" property');
  }

  if (!plugin.metadata.id) {
    throw new Error('Plugin metadata missing required "id" property');
  }

  if (!plugin.metadata.name) {
    throw new Error('Plugin metadata missing required "name" property');
  }

  if (!plugin.metadata.version) {
    throw new Error('Plugin metadata missing required "version" property');
  }

  // Type-specific validation
  switch (plugin.type) {
    case 'tool':
      if (!plugin.tools || typeof plugin.tools !== 'object') {
        throw new Error('Tool plugin missing required "tools" property');
      }
      break;
    case 'agent':
      if (!plugin.agents || typeof plugin.agents !== 'object') {
        throw new Error('Agent plugin missing required "agents" property');
      }
      break;
    case 'model-provider':
      if (!plugin.providers || typeof plugin.providers !== 'object') {
        throw new Error('Model provider plugin missing required "providers" property');
      }
      break;
    case 'prompt':
      if (!plugin.prompts || typeof plugin.prompts !== 'object') {
        throw new Error('Prompt plugin missing required "prompts" property');
      }
      break;
    case 'hook':
      if (!plugin.hooks || typeof plugin.hooks !== 'object') {
        throw new Error('Hook plugin missing required "hooks" property');
      }
      break;
  }

  return true;
}

/**
 * Load a plugin from a local file path
 */
export async function loadFromPath(
  pluginPath: string,
  options: LoadPluginOptions = {}
): Promise<Plugin> {
  const absolutePath = resolve(pluginPath);

  if (!existsSync(absolutePath)) {
    throw new Error(`Plugin path does not exist: ${absolutePath}`);
  }

  let modulePath = absolutePath;
  let manifest: PluginManifest | undefined;

  // Check if it's a directory with a package.json or pensar-plugin.json
  const stat = await import('fs/promises').then(m => m.stat(absolutePath));
  if (stat.isDirectory()) {
    // Try to find manifest
    const pensarManifestPath = join(absolutePath, 'pensar-plugin.json');
    const packageJsonPath = join(absolutePath, 'package.json');

    if (existsSync(pensarManifestPath)) {
      manifest = JSON.parse(readFileSync(pensarManifestPath, 'utf-8'));
      modulePath = join(absolutePath, manifest!.main);
    } else if (existsSync(packageJsonPath)) {
      const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
      if (packageJson.pensar) {
        manifest = { ...packageJson.pensar, ...packageJson };
        modulePath = join(absolutePath, packageJson.main || 'index.js');
      } else {
        modulePath = join(absolutePath, packageJson.main || 'index.js');
      }
    } else {
      // Try common entry points
      for (const entry of ['index.ts', 'index.js', 'plugin.ts', 'plugin.js']) {
        const entryPath = join(absolutePath, entry);
        if (existsSync(entryPath)) {
          modulePath = entryPath;
          break;
        }
      }
    }
  }

  // Import the module
  const module = await import(modulePath);
  const plugin = module.default || module.plugin || module;

  // Validate plugin
  if (!options.skipValidation) {
    validatePlugin(plugin);
  }

  // Register the plugin
  const registry = options.registry || getPluginRegistry();
  await registry.register(plugin, { type: 'local', path: absolutePath });

  return plugin;
}

/**
 * Load a plugin from an NPM package
 */
export async function loadFromNpm(
  packageName: string,
  version?: string,
  options: LoadPluginOptions = {}
): Promise<Plugin> {
  try {
    // Try to import the package directly (assumes it's installed)
    const module = await import(packageName);
    const plugin = module.default || module.plugin || module;

    if (!options.skipValidation) {
      validatePlugin(plugin);
    }

    const registry = options.registry || getPluginRegistry();
    await registry.register(plugin, { type: 'npm', package: packageName, version });

    return plugin;
  } catch (error: any) {
    throw new Error(`Failed to load NPM plugin '${packageName}': ${error.message}`);
  }
}

/**
 * Get the default plugins directory
 */
export function getPluginsDir(): string {
  return join(os.homedir(), '.pensar', 'plugins');
}

/**
 * Discover plugins in a directory
 */
export async function discoverPlugins(
  directory?: string
): Promise<DiscoveredPlugin[]> {
  const pluginsDir = directory || getPluginsDir();
  const discovered: DiscoveredPlugin[] = [];

  if (!existsSync(pluginsDir)) {
    return discovered;
  }

  const entries = readdirSync(pluginsDir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(pluginsDir, entry.name);

    if (entry.isDirectory()) {
      // Check for plugin manifest
      const pensarManifestPath = join(fullPath, 'pensar-plugin.json');
      const packageJsonPath = join(fullPath, 'package.json');

      let manifest: PluginManifest | undefined;

      if (existsSync(pensarManifestPath)) {
        try {
          manifest = JSON.parse(readFileSync(pensarManifestPath, 'utf-8'));
        } catch {
          // Invalid manifest, skip
        }
      } else if (existsSync(packageJsonPath)) {
        try {
          const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
          if (packageJson.pensar) {
            manifest = { ...packageJson.pensar, ...packageJson };
          }
        } catch {
          // Invalid package.json, skip
        }
      }

      discovered.push({
        path: fullPath,
        manifest,
        source: { type: 'local', path: fullPath },
      });
    } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.js'))) {
      // Single file plugin
      discovered.push({
        path: fullPath,
        source: { type: 'local', path: fullPath },
      });
    }
  }

  return discovered;
}

/**
 * Load all plugins from a directory
 */
export async function loadPluginsFromDirectory(
  directory?: string,
  options: LoadPluginOptions = {}
): Promise<Plugin[]> {
  const discovered = await discoverPlugins(directory);
  const loaded: Plugin[] = [];

  for (const { path, source } of discovered) {
    try {
      const plugin = await loadFromPath(path, options);
      loaded.push(plugin);
    } catch (error: any) {
      console.warn(`Failed to load plugin from ${path}: ${error.message}`);
    }
  }

  return loaded;
}

/**
 * Plugin loader configuration from pensar config
 */
export interface PluginLoaderConfig {
  /** Paths to load plugins from */
  paths?: string[];
  /** NPM packages to load */
  packages?: string[];
  /** Disabled plugin IDs */
  disabled?: string[];
  /** Auto-discover from default directory */
  autoDiscover?: boolean;
}

/**
 * Load plugins based on configuration
 */
export async function loadPluginsFromConfig(
  config: PluginLoaderConfig,
  options: LoadPluginOptions = {}
): Promise<Plugin[]> {
  const loaded: Plugin[] = [];

  // Load from paths
  if (config.paths) {
    for (const path of config.paths) {
      try {
        const plugin = await loadFromPath(path, options);
        loaded.push(plugin);
      } catch (error: any) {
        console.warn(`Failed to load plugin from path ${path}: ${error.message}`);
      }
    }
  }

  // Load from NPM packages
  if (config.packages) {
    for (const pkg of config.packages) {
      try {
        const [packageName, version] = pkg.split('@');
        const plugin = await loadFromNpm(packageName, version, options);
        loaded.push(plugin);
      } catch (error: any) {
        console.warn(`Failed to load plugin from package ${pkg}: ${error.message}`);
      }
    }
  }

  // Auto-discover from default directory
  if (config.autoDiscover !== false) {
    try {
      const discovered = await loadPluginsFromDirectory(undefined, options);
      loaded.push(...discovered);
    } catch (error: any) {
      console.warn(`Failed to auto-discover plugins: ${error.message}`);
    }
  }

  // Disable plugins as specified
  if (config.disabled) {
    const registry = options.registry || getPluginRegistry();
    for (const id of config.disabled) {
      if (registry.has(id)) {
        registry.disable(id);
      }
    }
  }

  return loaded;
}
