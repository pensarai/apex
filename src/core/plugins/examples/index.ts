/**
 * Example Plugins
 * 
 * These plugins demonstrate how to extend Pensar with custom functionality.
 * Use them as templates for building your own plugins.
 */

// Tool Plugin Example
export { headerScannerPlugin } from './header-scanner-plugin';

// Agent Plugin Example  
export { corsTesterPlugin } from './cors-tester-agent';

// Model Provider Plugin Example
export { ollamaProviderPlugin } from './ollama-provider-plugin';

// Hook Plugin Example
export { notificationPlugin } from './notification-hook-plugin';

/**
 * Load all example plugins
 */
export async function loadExamplePlugins() {
  const { getPluginRegistry } = await import('../registry');
  const registry = getPluginRegistry();

  const { headerScannerPlugin } = await import('./header-scanner-plugin');
  const { corsTesterPlugin } = await import('./cors-tester-agent');
  const { ollamaProviderPlugin } = await import('./ollama-provider-plugin');
  const { notificationPlugin } = await import('./notification-hook-plugin');

  await registry.register(headerScannerPlugin, { type: 'builtin' });
  await registry.register(corsTesterPlugin, { type: 'builtin' });
  await registry.register(ollamaProviderPlugin, { type: 'builtin' });
  await registry.register(notificationPlugin, { type: 'builtin' });

  return [
    headerScannerPlugin,
    corsTesterPlugin,
    ollamaProviderPlugin,
    notificationPlugin,
  ];
}
