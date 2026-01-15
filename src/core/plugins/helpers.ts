/**
 * Pensar Plugin System - Plugin Creation Helpers
 * 
 * Utility functions for creating plugins with proper typing and validation.
 */

import type {
  PluginMetadata,
  ToolPlugin,
  AgentPlugin,
  ModelProviderPlugin,
  PromptPlugin,
  HookPlugin,
  ToolDefinition,
  AgentDefinition,
  ModelProviderDefinition,
  PromptDefinition,
  HookEvent,
  HookHandler,
} from './types';

/**
 * Options for creating a tool plugin
 */
export interface CreateToolPluginOptions {
  metadata: PluginMetadata;
  tools: Record<string, ToolDefinition>;
  category?: ToolPlugin['category'];
  onLoad?: () => Promise<void> | void;
  onUnload?: () => Promise<void> | void;
}

/**
 * Create a tool plugin
 * 
 * @example
 * ```typescript
 * const plugin = createToolPlugin({
 *   metadata: {
 *     id: 'custom-scanner',
 *     name: 'Custom Scanner',
 *     version: '1.0.0',
 *     description: 'Custom security scanner tools',
 *   },
 *   tools: {
 *     scan_headers: {
 *       description: 'Scan HTTP headers for security issues',
 *       parameters: z.object({ url: z.string().url() }),
 *       execute: async ({ url }, context) => {
 *         // Implementation
 *         return { vulnerable: false, headers: {} };
 *       },
 *     },
 *   },
 * });
 * ```
 */
export function createToolPlugin(options: CreateToolPluginOptions): ToolPlugin {
  return {
    type: 'tool',
    metadata: options.metadata,
    tools: options.tools,
    category: options.category,
    onLoad: options.onLoad,
    onUnload: options.onUnload,
  };
}

/**
 * Options for creating an agent plugin
 */
export interface CreateAgentPluginOptions {
  metadata: PluginMetadata;
  agents: Record<string, AgentDefinition>;
  onLoad?: () => Promise<void> | void;
  onUnload?: () => Promise<void> | void;
}

/**
 * Create an agent plugin
 * 
 * @example
 * ```typescript
 * const plugin = createAgentPlugin({
 *   metadata: {
 *     id: 'api-tester',
 *     name: 'API Testing Agent',
 *     version: '1.0.0',
 *     description: 'Specialized API security testing',
 *   },
 *   agents: {
 *     api_security_agent: {
 *       description: 'Tests API endpoints for security vulnerabilities',
 *       vulnerabilityClasses: ['injection', 'auth_bypass'],
 *       execute: async (input, context) => {
 *         // Implementation
 *         return { success: true, findingsCount: 0, summary: 'Complete' };
 *       },
 *     },
 *   },
 * });
 * ```
 */
export function createAgentPlugin(options: CreateAgentPluginOptions): AgentPlugin {
  return {
    type: 'agent',
    metadata: options.metadata,
    agents: options.agents,
    onLoad: options.onLoad,
    onUnload: options.onUnload,
  };
}

/**
 * Options for creating a model provider plugin
 */
export interface CreateModelProviderPluginOptions {
  metadata: PluginMetadata;
  providers: Record<string, ModelProviderDefinition>;
  onLoad?: () => Promise<void> | void;
  onUnload?: () => Promise<void> | void;
}

/**
 * Create a model provider plugin
 * 
 * @example
 * ```typescript
 * const plugin = createModelProviderPlugin({
 *   metadata: {
 *     id: 'ollama-provider',
 *     name: 'Ollama Provider',
 *     version: '1.0.0',
 *     description: 'Support for local Ollama models',
 *   },
 *   providers: {
 *     ollama: {
 *       description: 'Local Ollama models',
 *       models: [
 *         { id: 'ollama:llama3', name: 'Llama 3', provider: 'ollama' },
 *         { id: 'ollama:codellama', name: 'Code Llama', provider: 'ollama' },
 *       ],
 *       createProvider: (config) => createOllama({ baseURL: config.baseUrl }),
 *       isAvailable: () => true,
 *     },
 *   },
 * });
 * ```
 */
export function createModelProviderPlugin(options: CreateModelProviderPluginOptions): ModelProviderPlugin {
  return {
    type: 'model-provider',
    metadata: options.metadata,
    providers: options.providers,
    onLoad: options.onLoad,
    onUnload: options.onUnload,
  };
}

/**
 * Options for creating a prompt plugin
 */
export interface CreatePromptPluginOptions {
  metadata: PluginMetadata;
  prompts: Record<string, PromptDefinition>;
  onLoad?: () => Promise<void> | void;
  onUnload?: () => Promise<void> | void;
}

/**
 * Create a prompt plugin
 * 
 * @example
 * ```typescript
 * const plugin = createPromptPlugin({
 *   metadata: {
 *     id: 'jwt-testing',
 *     name: 'JWT Security Testing Prompts',
 *     version: '1.0.0',
 *     description: 'Specialized prompts for JWT security testing',
 *   },
 *   prompts: {
 *     jwt_attack: {
 *       description: 'JWT token manipulation attacks',
 *       vulnerabilityClass: 'auth_bypass',
 *       techniques: [
 *         { name: 'None Algorithm', description: 'Set alg to none' },
 *         { name: 'Key Confusion', description: 'RS256 to HS256' },
 *       ],
 *       vulnerableIndicators: ['Token accepted with modified claims'],
 *       notVulnerableIndicators: ['Token signature validation failed'],
 *     },
 *   },
 * });
 * ```
 */
export function createPromptPlugin(options: CreatePromptPluginOptions): PromptPlugin {
  return {
    type: 'prompt',
    metadata: options.metadata,
    prompts: options.prompts,
    onLoad: options.onLoad,
    onUnload: options.onUnload,
  };
}

/**
 * Options for creating a hook plugin
 */
export interface CreateHookPluginOptions {
  metadata: PluginMetadata;
  hooks: Partial<Record<HookEvent, HookHandler>>;
  onLoad?: () => Promise<void> | void;
  onUnload?: () => Promise<void> | void;
}

/**
 * Create a hook plugin
 * 
 * @example
 * ```typescript
 * const plugin = createHookPlugin({
 *   metadata: {
 *     id: 'slack-notifier',
 *     name: 'Slack Notifier',
 *     version: '1.0.0',
 *     description: 'Send Slack notifications for findings',
 *   },
 *   hooks: {
 *     'finding:discovered': async (data) => {
 *       await sendSlackMessage(`New finding: ${data.title}`);
 *     },
 *     'session:end': async (data) => {
 *       await sendSlackMessage(`Session complete: ${data.findingsCount} findings`);
 *     },
 *   },
 * });
 * ```
 */
export function createHookPlugin(options: CreateHookPluginOptions): HookPlugin {
  return {
    type: 'hook',
    metadata: options.metadata,
    hooks: options.hooks,
    onLoad: options.onLoad,
    onUnload: options.onUnload,
  };
}

/**
 * Define a tool with proper typing
 */
export function defineTool<TParams, TResult>(
  definition: {
    description: string;
    parameters: TParams;
    execute: (params: any, context: any) => Promise<TResult>;
  }
): ToolDefinition {
  return definition as ToolDefinition;
}

/**
 * Define an agent with proper typing
 */
export function defineAgent(definition: AgentDefinition): AgentDefinition {
  return definition;
}

/**
 * Define a model provider with proper typing
 */
export function defineModelProvider(definition: ModelProviderDefinition): ModelProviderDefinition {
  return definition;
}

/**
 * Define a prompt with proper typing
 */
export function definePrompt(definition: PromptDefinition): PromptDefinition {
  return definition;
}
