/**
 * Plugin System Tests
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { z } from 'zod';
import {
  PluginRegistry,
  resetPluginRegistry,
  getPluginRegistry,
  createToolPlugin,
  createAgentPlugin,
  createHookPlugin,
  type ToolPlugin,
  type AgentPlugin,
  type HookPlugin,
  type Plugin,
} from './index';

describe('PluginRegistry', () => {
  let registry: PluginRegistry;

  beforeEach(() => {
    resetPluginRegistry();
    registry = new PluginRegistry();
  });

  afterEach(() => {
    resetPluginRegistry();
  });

  describe('register', () => {
    it('should register a plugin', async () => {
      const plugin = createToolPlugin({
        metadata: {
          id: 'test-plugin',
          name: 'Test Plugin',
          version: '1.0.0',
          description: 'A test plugin',
        },
        tools: {},
      });

      await registry.register(plugin);

      expect(registry.has('test-plugin')).toBe(true);
      expect(registry.get('test-plugin')?.plugin).toBe(plugin);
    });

    it('should throw if plugin is already registered', async () => {
      const plugin = createToolPlugin({
        metadata: {
          id: 'test-plugin',
          name: 'Test Plugin',
          version: '1.0.0',
          description: 'A test plugin',
        },
        tools: {},
      });

      await registry.register(plugin);

      await expect(registry.register(plugin)).rejects.toThrow(
        "Plugin with ID 'test-plugin' is already registered"
      );
    });

    it('should check dependencies', async () => {
      const plugin = createToolPlugin({
        metadata: {
          id: 'dependent-plugin',
          name: 'Dependent Plugin',
          version: '1.0.0',
          description: 'Depends on another plugin',
          dependencies: ['base-plugin'],
        },
        tools: {},
      });

      await expect(registry.register(plugin)).rejects.toThrow(
        "requires dependency 'base-plugin'"
      );
    });

    it('should call onLoad hook', async () => {
      let loaded = false;
      const plugin = createToolPlugin({
        metadata: {
          id: 'test-plugin',
          name: 'Test Plugin',
          version: '1.0.0',
          description: 'A test plugin',
        },
        tools: {},
        onLoad: () => {
          loaded = true;
        },
      });

      await registry.register(plugin);

      expect(loaded).toBe(true);
    });
  });

  describe('unregister', () => {
    it('should unregister a plugin', async () => {
      const plugin = createToolPlugin({
        metadata: {
          id: 'test-plugin',
          name: 'Test Plugin',
          version: '1.0.0',
          description: 'A test plugin',
        },
        tools: {},
      });

      await registry.register(plugin);
      await registry.unregister('test-plugin');

      expect(registry.has('test-plugin')).toBe(false);
    });

    it('should throw if plugin is not registered', async () => {
      await expect(registry.unregister('non-existent')).rejects.toThrow(
        "Plugin 'non-existent' is not registered"
      );
    });

    it('should prevent unregistering if other plugins depend on it', async () => {
      const basePlugin = createToolPlugin({
        metadata: {
          id: 'base-plugin',
          name: 'Base Plugin',
          version: '1.0.0',
          description: 'Base plugin',
        },
        tools: {},
      });

      const dependentPlugin = createToolPlugin({
        metadata: {
          id: 'dependent-plugin',
          name: 'Dependent Plugin',
          version: '1.0.0',
          description: 'Depends on base',
          dependencies: ['base-plugin'],
        },
        tools: {},
      });

      await registry.register(basePlugin);
      await registry.register(dependentPlugin);

      await expect(registry.unregister('base-plugin')).rejects.toThrow(
        "Cannot unregister 'base-plugin': plugin 'dependent-plugin' depends on it"
      );
    });

    it('should call onUnload hook', async () => {
      let unloaded = false;
      const plugin = createToolPlugin({
        metadata: {
          id: 'test-plugin',
          name: 'Test Plugin',
          version: '1.0.0',
          description: 'A test plugin',
        },
        tools: {},
        onUnload: () => {
          unloaded = true;
        },
      });

      await registry.register(plugin);
      await registry.unregister('test-plugin');

      expect(unloaded).toBe(true);
    });
  });

  describe('enable/disable', () => {
    it('should enable a plugin', async () => {
      const plugin = createToolPlugin({
        metadata: {
          id: 'test-plugin',
          name: 'Test Plugin',
          version: '1.0.0',
          description: 'A test plugin',
        },
        tools: {},
      });

      await registry.register(plugin);
      registry.disable('test-plugin');
      
      expect(registry.get('test-plugin')?.status).toBe('disabled');
      
      registry.enable('test-plugin');
      
      expect(registry.get('test-plugin')?.status).toBe('enabled');
    });
  });

  describe('getByType', () => {
    it('should return plugins by type', async () => {
      const toolPlugin = createToolPlugin({
        metadata: {
          id: 'tool-plugin',
          name: 'Tool Plugin',
          version: '1.0.0',
          description: 'A tool plugin',
        },
        tools: {},
      });

      const agentPlugin = createAgentPlugin({
        metadata: {
          id: 'agent-plugin',
          name: 'Agent Plugin',
          version: '1.0.0',
          description: 'An agent plugin',
        },
        agents: {},
      });

      await registry.register(toolPlugin);
      await registry.register(agentPlugin);

      const toolPlugins = registry.getToolPlugins();
      const agentPlugins = registry.getAgentPlugins();

      expect(toolPlugins).toHaveLength(1);
      expect(toolPlugins[0].metadata.id).toBe('tool-plugin');

      expect(agentPlugins).toHaveLength(1);
      expect(agentPlugins[0].metadata.id).toBe('agent-plugin');
    });
  });

  describe('getAllTools', () => {
    it('should aggregate tools from all plugins', async () => {
      const plugin1 = createToolPlugin({
        metadata: {
          id: 'plugin-1',
          name: 'Plugin 1',
          version: '1.0.0',
          description: 'First plugin',
        },
        tools: {
          tool_a: {
            description: 'Tool A',
            parameters: z.object({}),
            execute: async () => ({ result: 'a' }),
          },
        },
      });

      const plugin2 = createToolPlugin({
        metadata: {
          id: 'plugin-2',
          name: 'Plugin 2',
          version: '1.0.0',
          description: 'Second plugin',
        },
        tools: {
          tool_b: {
            description: 'Tool B',
            parameters: z.object({}),
            execute: async () => ({ result: 'b' }),
          },
        },
      });

      await registry.register(plugin1);
      await registry.register(plugin2);

      const allTools = registry.getAllTools();

      // Should have both namespaced and non-namespaced versions
      expect(allTools['plugin-1:tool_a']).toBeDefined();
      expect(allTools['plugin-2:tool_b']).toBeDefined();
      expect(allTools['tool_a']).toBeDefined();
      expect(allTools['tool_b']).toBeDefined();
    });
  });

  describe('executeHooks', () => {
    it('should execute hooks from all hook plugins', async () => {
      const results: string[] = [];

      const hookPlugin = createHookPlugin({
        metadata: {
          id: 'hook-plugin',
          name: 'Hook Plugin',
          version: '1.0.0',
          description: 'A hook plugin',
        },
        hooks: {
          'session:start': async (data: any) => {
            results.push(`session started: ${data.id}`);
          },
          'finding:discovered': async (data: any) => {
            results.push(`finding: ${data.title}`);
          },
        },
      });

      await registry.register(hookPlugin);

      await registry.executeHooks('session:start', { id: 'test-session' });
      await registry.executeHooks('finding:discovered', { title: 'XSS Vulnerability' });

      expect(results).toContain('session started: test-session');
      expect(results).toContain('finding: XSS Vulnerability');
    });
  });

  describe('getStats', () => {
    it('should return accurate statistics', async () => {
      const toolPlugin = createToolPlugin({
        metadata: {
          id: 'tool-plugin',
          name: 'Tool Plugin',
          version: '1.0.0',
          description: 'A tool plugin',
        },
        tools: {},
      });

      const agentPlugin = createAgentPlugin({
        metadata: {
          id: 'agent-plugin',
          name: 'Agent Plugin',
          version: '1.0.0',
          description: 'An agent plugin',
        },
        agents: {},
      });

      await registry.register(toolPlugin);
      await registry.register(agentPlugin);
      registry.disable('agent-plugin');

      const stats = registry.getStats();

      expect(stats.total).toBe(2);
      expect(stats.byType.tool).toBe(1);
      expect(stats.byType.agent).toBe(1);
      expect(stats.byStatus.enabled).toBe(1);
      expect(stats.byStatus.disabled).toBe(1);
    });
  });
});

describe('Global Registry', () => {
  beforeEach(() => {
    resetPluginRegistry();
  });

  afterEach(() => {
    resetPluginRegistry();
  });

  it('should return the same instance', () => {
    const registry1 = getPluginRegistry();
    const registry2 = getPluginRegistry();

    expect(registry1).toBe(registry2);
  });

  it('should reset correctly', async () => {
    const registry = getPluginRegistry();
    
    const plugin = createToolPlugin({
      metadata: {
        id: 'test-plugin',
        name: 'Test Plugin',
        version: '1.0.0',
        description: 'A test plugin',
      },
      tools: {},
    });

    await registry.register(plugin);
    expect(registry.has('test-plugin')).toBe(true);

    resetPluginRegistry();
    
    const newRegistry = getPluginRegistry();
    expect(newRegistry.has('test-plugin')).toBe(false);
  });
});

describe('Plugin Creation Helpers', () => {
  describe('createToolPlugin', () => {
    it('should create a valid tool plugin', () => {
      const plugin = createToolPlugin({
        metadata: {
          id: 'test-tool-plugin',
          name: 'Test Tool Plugin',
          version: '1.0.0',
          description: 'A test tool plugin',
        },
        tools: {
          test_tool: {
            description: 'A test tool',
            parameters: z.object({
              input: z.string(),
            }),
            execute: async ({ input }) => ({ output: input.toUpperCase() }),
          },
        },
        category: 'utility',
      });

      expect(plugin.type).toBe('tool');
      expect(plugin.metadata.id).toBe('test-tool-plugin');
      expect(plugin.tools.test_tool).toBeDefined();
      expect(plugin.category).toBe('utility');
    });
  });

  describe('createAgentPlugin', () => {
    it('should create a valid agent plugin', () => {
      const plugin = createAgentPlugin({
        metadata: {
          id: 'test-agent-plugin',
          name: 'Test Agent Plugin',
          version: '1.0.0',
          description: 'A test agent plugin',
        },
        agents: {
          test_agent: {
            description: 'A test agent',
            execute: async (input, context) => ({
              success: true,
              findingsCount: 0,
              summary: 'Test complete',
            }),
          },
        },
      });

      expect(plugin.type).toBe('agent');
      expect(plugin.metadata.id).toBe('test-agent-plugin');
      expect(plugin.agents.test_agent).toBeDefined();
    });
  });

  describe('createHookPlugin', () => {
    it('should create a valid hook plugin', () => {
      const plugin = createHookPlugin({
        metadata: {
          id: 'test-hook-plugin',
          name: 'Test Hook Plugin',
          version: '1.0.0',
          description: 'A test hook plugin',
        },
        hooks: {
          'session:start': async (data) => {
            console.log('Session started:', data);
          },
        },
      });

      expect(plugin.type).toBe('hook');
      expect(plugin.metadata.id).toBe('test-hook-plugin');
      expect(plugin.hooks['session:start']).toBeDefined();
    });
  });
});

describe('Tool Execution', () => {
  let registry: PluginRegistry;

  beforeEach(() => {
    resetPluginRegistry();
    registry = new PluginRegistry();
  });

  afterEach(() => {
    resetPluginRegistry();
  });

  it('should execute a tool with correct context', async () => {
    let capturedContext: any = null;

    const plugin = createToolPlugin({
      metadata: {
        id: 'context-test-plugin',
        name: 'Context Test Plugin',
        version: '1.0.0',
        description: 'Tests tool context',
      },
      tools: {
        context_test: {
          description: 'Tests context',
          parameters: z.object({}),
          execute: async (params, context) => {
            capturedContext = context;
            return { received: true };
          },
        },
      },
    });

    await registry.register(plugin);

    const mockSession = {
      id: 'test-session',
      rootPath: '/tmp/test',
    };
    const mockModel = 'gpt-4';

    const toolSet = registry.createToolSet({
      session: mockSession as any,
      model: mockModel,
      log: () => {},
      getConfig: () => undefined,
    });

    const result = await toolSet['context_test'].execute({});

    expect(result.received).toBe(true);
    expect(capturedContext).not.toBeNull();
    expect(capturedContext.session.id).toBe('test-session');
    expect(capturedContext.model).toBe('gpt-4');
  });
});
