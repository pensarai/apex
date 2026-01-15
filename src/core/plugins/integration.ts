/**
 * Pensar Plugin System - Integration Utilities
 * 
 * Helper functions for integrating the plugin system with Pensar's core functionality.
 */

import { tool } from 'ai';
import type { ToolSet } from 'ai';
import type { Session } from '../session';
import type { AIModel, ModelInfo } from '../ai';
import { getPluginRegistry, type PluginRegistry } from './registry';
import type {
  ToolPluginContext,
  ToolDefinition,
  AgentPluginContext,
} from './types';

/**
 * Create a tool context for plugin tools
 */
export function createToolContext(
  session: Session.SessionInfo,
  model: AIModel
): ToolPluginContext {
  return {
    session,
    model,
    log: (message, level = 'info') => {
      const timestamp = new Date().toISOString();
      const prefix = `[${level.toUpperCase()}] ${timestamp}`;
      switch (level) {
        case 'error':
          console.error(`${prefix} ${message}`);
          break;
        case 'warn':
          console.warn(`${prefix} ${message}`);
          break;
        case 'debug':
          if (process.env.DEBUG) {
            console.log(`${prefix} ${message}`);
          }
          break;
        default:
          console.log(`${prefix} ${message}`);
      }
    },
    getConfig: <T>(key: string): T | undefined => {
      return session.config?.[key as keyof typeof session.config] as T | undefined;
    },
  };
}

/**
 * Convert a plugin tool definition to an AI SDK tool
 */
export function convertPluginTool(
  name: string,
  toolDef: ToolDefinition,
  context: ToolPluginContext
): any {
  return tool({
    description: toolDef.description,
    parameters: toolDef.parameters,
    execute: async (params: any) => {
      return toolDef.execute(params, context);
    },
  });
}

/**
 * Get all plugin tools as an AI SDK ToolSet
 */
export function getPluginToolSet(
  session: Session.SessionInfo,
  model: AIModel,
  registry?: PluginRegistry
): Record<string, any> {
  const reg = registry || getPluginRegistry();
  const context = createToolContext(session, model);
  const toolSet: Record<string, any> = {};

  const allTools = reg.getAllTools();
  
  for (const [name, { tool: toolDef }] of Object.entries(allTools)) {
    toolSet[name] = convertPluginTool(name, toolDef, context);
  }

  return toolSet;
}

/**
 * Merge built-in tools with plugin tools
 */
export function mergeToolSets(
  builtinTools: Record<string, any>,
  pluginTools: Record<string, any>
): Record<string, any> {
  // Plugin tools can override built-in tools if they have the same name
  // To avoid this, plugin tools are namespaced (plugin-id:tool-name)
  return {
    ...builtinTools,
    ...pluginTools,
  };
}

/**
 * Create an agent context for plugin agents
 */
export function createAgentContext(
  session: Session.SessionInfo,
  model: AIModel,
  tools: ToolSet,
  abortSignal?: AbortSignal
): AgentPluginContext {
  return {
    session,
    model,
    tools,
    log: (message, level = 'info') => {
      const timestamp = new Date().toISOString();
      const prefix = `[${level.toUpperCase()}] ${timestamp}`;
      switch (level) {
        case 'error':
          console.error(`${prefix} ${message}`);
          break;
        case 'warn':
          console.warn(`${prefix} ${message}`);
          break;
        case 'debug':
          if (process.env.DEBUG) {
            console.log(`${prefix} ${message}`);
          }
          break;
        default:
          console.log(`${prefix} ${message}`);
      }
    },
    abortSignal,
  };
}

/**
 * Get all available models including plugins
 */
export function getAllAvailableModels(registry?: PluginRegistry): ModelInfo[] {
  const reg = registry || getPluginRegistry();
  const models: ModelInfo[] = [];

  // Get models from plugin providers
  const providers = reg.getAllModelProviders();
  for (const { provider } of Object.values(providers)) {
    models.push(...provider.models);
  }

  return models;
}

/**
 * Execute hooks for a plugin event
 */
export async function executePluginHooks<T>(
  event: string,
  data: T,
  registry?: PluginRegistry
): Promise<void> {
  const reg = registry || getPluginRegistry();
  await reg.executeHooks(event as any, data);
}

/**
 * Check if a model is from a plugin provider
 */
export function isPluginModel(modelId: string, registry?: PluginRegistry): boolean {
  const reg = registry || getPluginRegistry();
  const models = getAllAvailableModels(reg);
  return models.some(m => m.id === modelId);
}

/**
 * Get the provider for a plugin model
 */
export function getPluginModelProvider(
  modelId: string,
  registry?: PluginRegistry
): { provider: any; config: any } | undefined {
  const reg = registry || getPluginRegistry();
  const providers = reg.getAllModelProviders();

  for (const { provider } of Object.values(providers)) {
    const model = provider.models.find((m: ModelInfo) => m.id === modelId);
    if (model) {
      return {
        provider: provider.createProvider({}),
        config: {},
      };
    }
  }

  return undefined;
}
