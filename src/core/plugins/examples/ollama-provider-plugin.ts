/**
 * Example Model Provider Plugin: Ollama
 * 
 * This plugin demonstrates how to create a model provider plugin
 * that adds support for local Ollama models.
 */

import { createModelProviderPlugin, type ModelProviderConfig } from '../index';
import type { ModelInfo } from '../../ai';

/**
 * Available Ollama models
 */
const OLLAMA_MODELS: ModelInfo[] = [
  {
    id: 'ollama:llama3.2',
    name: 'Llama 3.2 (8B)',
    provider: 'ollama',
  },
  {
    id: 'ollama:llama3.2:70b',
    name: 'Llama 3.2 (70B)',
    provider: 'ollama',
  },
  {
    id: 'ollama:codellama',
    name: 'Code Llama',
    provider: 'ollama',
  },
  {
    id: 'ollama:deepseek-coder',
    name: 'DeepSeek Coder',
    provider: 'ollama',
  },
  {
    id: 'ollama:mistral',
    name: 'Mistral 7B',
    provider: 'ollama',
  },
  {
    id: 'ollama:mixtral',
    name: 'Mixtral 8x7B',
    provider: 'ollama',
  },
  {
    id: 'ollama:qwen2.5-coder',
    name: 'Qwen 2.5 Coder',
    provider: 'ollama',
  },
];

/**
 * Default Ollama API URL
 */
const DEFAULT_OLLAMA_URL = 'http://localhost:11434';

/**
 * Check if Ollama is running
 */
async function checkOllamaAvailable(baseUrl: string): Promise<boolean> {
  try {
    const response = await fetch(`${baseUrl}/api/version`, {
      method: 'GET',
      signal: AbortSignal.timeout(2000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Get list of models available on the Ollama server
 */
async function getAvailableModels(baseUrl: string): Promise<string[]> {
  try {
    const response = await fetch(`${baseUrl}/api/tags`);
    if (!response.ok) return [];
    const data = await response.json();
    return data.models?.map((m: any) => m.name) || [];
  } catch {
    return [];
  }
}

/**
 * Create an Ollama-compatible provider
 * 
 * Note: This is a simplified implementation. In a real plugin,
 * you would implement the full AI SDK provider interface.
 */
function createOllamaProvider(config: ModelProviderConfig) {
  const baseUrl = config.baseUrl || DEFAULT_OLLAMA_URL;

  return {
    baseUrl,
    
    // Provider metadata
    provider: 'ollama',
    
    // Generate completion
    async generateCompletion(params: {
      model: string;
      prompt: string;
      system?: string;
      options?: any;
    }) {
      const modelName = params.model.replace('ollama:', '');
      
      const response = await fetch(`${baseUrl}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: modelName,
          prompt: params.prompt,
          system: params.system,
          stream: false,
          ...params.options,
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama API error: ${response.statusText}`);
      }

      const data = await response.json();
      return {
        text: data.response,
        usage: {
          promptTokens: data.prompt_eval_count || 0,
          completionTokens: data.eval_count || 0,
        },
      };
    },

    // Chat completion
    async chat(params: {
      model: string;
      messages: Array<{ role: string; content: string }>;
      options?: any;
    }) {
      const modelName = params.model.replace('ollama:', '');
      
      const response = await fetch(`${baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: modelName,
          messages: params.messages,
          stream: false,
          ...params.options,
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama API error: ${response.statusText}`);
      }

      const data = await response.json();
      return {
        message: data.message,
        usage: {
          promptTokens: data.prompt_eval_count || 0,
          completionTokens: data.eval_count || 0,
        },
      };
    },

    // List available models
    async listModels() {
      return getAvailableModels(baseUrl);
    },
  };
}

/**
 * Ollama Provider Plugin
 */
export const ollamaProviderPlugin = createModelProviderPlugin({
  metadata: {
    id: 'pensar-ollama-provider',
    name: 'Ollama Model Provider',
    version: '1.0.0',
    description: 'Support for local Ollama models',
    author: 'Pensar',
    tags: ['ai', 'ollama', 'local', 'llm'],
    homepage: 'https://ollama.ai',
  },
  providers: {
    ollama: {
      description: 'Local Ollama models for AI-powered security testing',
      models: OLLAMA_MODELS,
      
      createProvider: (config) => createOllamaProvider(config),
      
      validateConfig: (config) => {
        const baseUrl = config.baseUrl || DEFAULT_OLLAMA_URL;
        try {
          new URL(baseUrl);
          return { valid: true };
        } catch {
          return { valid: false, error: 'Invalid base URL' };
        }
      },
      
      isAvailable: (config) => {
        // For sync check, assume available if URL is valid
        // Real availability check happens at runtime
        const baseUrl = config.baseUrl || DEFAULT_OLLAMA_URL;
        try {
          new URL(baseUrl);
          return true;
        } catch {
          return false;
        }
      },
    },
  },
  
  onLoad: async () => {
    // Check if Ollama is running on startup
    const available = await checkOllamaAvailable(DEFAULT_OLLAMA_URL);
    if (available) {
      console.log('Ollama provider loaded - server detected at', DEFAULT_OLLAMA_URL);
      const models = await getAvailableModels(DEFAULT_OLLAMA_URL);
      if (models.length > 0) {
        console.log('Available Ollama models:', models.join(', '));
      }
    } else {
      console.log('Ollama provider loaded - server not detected (start Ollama to use local models)');
    }
  },
});

export default ollamaProviderPlugin;
