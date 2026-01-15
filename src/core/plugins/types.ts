/**
 * Pensar Plugin System - Type Definitions
 * 
 * This module defines the interfaces and types for the plugin system,
 * allowing third-party extensions for tools, agents, model providers, and prompts.
 */

import type { ToolSet, StreamTextResult } from 'ai';
import type { AIModel, ModelInfo } from '../ai';
import type { Session } from '../session';
import type { VulnerabilityClass } from '../agent/orchestrator/types';

// ============================================================================
// Base Plugin Types
// ============================================================================

/**
 * Supported plugin types
 */
export type PluginType = 'tool' | 'agent' | 'model-provider' | 'prompt' | 'hook';

/**
 * Plugin metadata common to all plugin types
 */
export interface PluginMetadata {
  /** Unique identifier for the plugin */
  id: string;
  /** Human-readable name */
  name: string;
  /** Version string (semver) */
  version: string;
  /** Plugin description */
  description: string;
  /** Plugin author */
  author?: string;
  /** Plugin homepage/repository URL */
  homepage?: string;
  /** Plugin license */
  license?: string;
  /** Tags for categorization */
  tags?: string[];
  /** Minimum Pensar version required */
  pensarVersion?: string;
  /** Plugin dependencies (other plugin IDs) */
  dependencies?: string[];
}

/**
 * Base interface for all plugins
 */
export interface BasePlugin {
  /** Plugin type discriminator */
  type: PluginType;
  /** Plugin metadata */
  metadata: PluginMetadata;
  /** Called when plugin is loaded */
  onLoad?: () => Promise<void> | void;
  /** Called when plugin is unloaded */
  onUnload?: () => Promise<void> | void;
}

// ============================================================================
// Tool Plugin Types
// ============================================================================

/**
 * Context provided to tool plugins
 */
export interface ToolPluginContext {
  /** Current session information */
  session: Session.SessionInfo;
  /** AI model being used */
  model: AIModel;
  /** Logger function */
  log: (message: string, level?: 'info' | 'warn' | 'error' | 'debug') => void;
  /** Get configuration value */
  getConfig: <T>(key: string) => T | undefined;
}

/**
 * Tool definition compatible with AI SDK
 */
export interface ToolDefinition {
  /** Tool description for the AI */
  description: string;
  /** Zod schema for parameters */
  parameters: any; // z.ZodSchema
  /** Tool execution function */
  execute: (params: any, context: ToolPluginContext) => Promise<any>;
}

/**
 * Plugin that provides custom tools
 */
export interface ToolPlugin extends BasePlugin {
  type: 'tool';
  /** Tools provided by this plugin */
  tools: Record<string, ToolDefinition>;
  /** Tool category for grouping in UI */
  category?: 'reconnaissance' | 'exploitation' | 'utility' | 'reporting' | 'custom';
}

// ============================================================================
// Agent Plugin Types
// ============================================================================

/**
 * Agent execution context
 */
export interface AgentPluginContext {
  /** Current session */
  session: Session.SessionInfo;
  /** AI model to use */
  model: AIModel;
  /** Available tools (including from other plugins) */
  tools: ToolSet;
  /** Logger function */
  log: (message: string, level?: 'info' | 'warn' | 'error' | 'debug') => void;
  /** Abort signal for cancellation */
  abortSignal?: AbortSignal;
}

/**
 * Agent execution input
 */
export interface AgentInput {
  /** Target URL or identifier */
  target: string;
  /** Testing objective */
  objective: string;
  /** Additional parameters specific to the agent */
  params?: Record<string, any>;
}

/**
 * Agent execution result
 */
export interface AgentResult {
  /** Whether the agent completed successfully */
  success: boolean;
  /** Number of findings discovered */
  findingsCount: number;
  /** Summary of the agent's work */
  summary: string;
  /** Paths to any generated artifacts */
  artifacts?: string[];
  /** Error message if unsuccessful */
  error?: string;
  /** Additional result data */
  data?: Record<string, any>;
}

/**
 * Agent definition
 */
export interface AgentDefinition {
  /** Agent description */
  description: string;
  /** Vulnerability classes this agent can test */
  vulnerabilityClasses?: VulnerabilityClass[];
  /** Whether this agent supports streaming */
  supportsStreaming?: boolean;
  /** Execute the agent */
  execute: (
    input: AgentInput,
    context: AgentPluginContext
  ) => Promise<AgentResult>;
  /** Execute with streaming (optional) */
  executeStreaming?: (
    input: AgentInput,
    context: AgentPluginContext,
    onStep?: (step: any) => void
  ) => Promise<{ streamResult: StreamTextResult<ToolSet, never>; result: Promise<AgentResult> }>;
}

/**
 * Plugin that provides custom agents
 */
export interface AgentPlugin extends BasePlugin {
  type: 'agent';
  /** Agents provided by this plugin */
  agents: Record<string, AgentDefinition>;
}

// ============================================================================
// Model Provider Plugin Types
// ============================================================================

/**
 * Model provider configuration
 */
export interface ModelProviderConfig {
  /** API key (if required) */
  apiKey?: string;
  /** Base URL (for self-hosted models) */
  baseUrl?: string;
  /** Additional provider-specific options */
  options?: Record<string, any>;
}

/**
 * Model provider definition
 */
export interface ModelProviderDefinition {
  /** Provider description */
  description: string;
  /** Available models */
  models: ModelInfo[];
  /** Create the AI provider instance */
  createProvider: (config: ModelProviderConfig) => any;
  /** Validate configuration */
  validateConfig?: (config: ModelProviderConfig) => { valid: boolean; error?: string };
  /** Check if provider is available (e.g., API key set) */
  isAvailable: (config: ModelProviderConfig) => boolean;
}

/**
 * Plugin that provides custom model providers
 */
export interface ModelProviderPlugin extends BasePlugin {
  type: 'model-provider';
  /** Providers offered by this plugin */
  providers: Record<string, ModelProviderDefinition>;
}

// ============================================================================
// Prompt Plugin Types
// ============================================================================

/**
 * Prompt template context variables
 */
export interface PromptTemplateContext {
  /** Target being tested */
  target?: string;
  /** Testing objective */
  objective?: string;
  /** Vulnerability class */
  vulnerabilityClass?: VulnerabilityClass;
  /** Authentication info */
  authInfo?: any;
  /** Additional context */
  [key: string]: any;
}

/**
 * Prompt definition
 */
export interface PromptDefinition {
  /** Prompt description */
  description: string;
  /** Vulnerability class this prompt is for */
  vulnerabilityClass?: VulnerabilityClass;
  /** System prompt template */
  systemPrompt?: string | ((context: PromptTemplateContext) => string);
  /** User prompt template */
  userPrompt?: string | ((context: PromptTemplateContext) => string);
  /** Indicators of vulnerability */
  vulnerableIndicators?: string[];
  /** Indicators of not vulnerable */
  notVulnerableIndicators?: string[];
  /** Attack techniques to try */
  techniques?: Array<{
    name: string;
    description: string;
    payloads?: string[];
  }>;
}

/**
 * Plugin that provides custom prompts
 */
export interface PromptPlugin extends BasePlugin {
  type: 'prompt';
  /** Prompts provided by this plugin */
  prompts: Record<string, PromptDefinition>;
}

// ============================================================================
// Hook Plugin Types
// ============================================================================

/**
 * Hook event types
 */
export type HookEvent =
  | 'session:start'
  | 'session:end'
  | 'agent:start'
  | 'agent:end'
  | 'tool:before'
  | 'tool:after'
  | 'finding:discovered'
  | 'test:start'
  | 'test:end';

/**
 * Hook handler function
 */
export type HookHandler<T = any> = (data: T) => Promise<void> | void;

/**
 * Plugin that provides lifecycle hooks
 */
export interface HookPlugin extends BasePlugin {
  type: 'hook';
  /** Hooks provided by this plugin */
  hooks: Partial<Record<HookEvent, HookHandler>>;
}

// ============================================================================
// Union Types
// ============================================================================

/**
 * Union of all plugin types
 */
export type Plugin = 
  | ToolPlugin 
  | AgentPlugin 
  | ModelProviderPlugin 
  | PromptPlugin 
  | HookPlugin;

/**
 * Plugin manifest for package.json or pensar-plugin.json
 */
export interface PluginManifest extends PluginMetadata {
  /** Main entry point */
  main: string;
  /** Plugin type */
  type: PluginType;
  /** Configuration schema */
  configSchema?: Record<string, any>;
}

// ============================================================================
// Plugin Discovery Types
// ============================================================================

/**
 * Source of a plugin
 */
export type PluginSource = 
  | { type: 'builtin' }
  | { type: 'local'; path: string }
  | { type: 'npm'; package: string; version?: string }
  | { type: 'url'; url: string };

/**
 * Plugin status in the registry
 */
export type PluginStatus = 'installed' | 'loaded' | 'enabled' | 'disabled' | 'error';

/**
 * Plugin registration entry
 */
export interface PluginEntry {
  /** The plugin instance */
  plugin: Plugin;
  /** Plugin source */
  source: PluginSource;
  /** Current status */
  status: PluginStatus;
  /** Error message if status is 'error' */
  error?: string;
  /** When the plugin was loaded */
  loadedAt?: Date;
}
