#!/usr/bin/env bun

/**
 * Pensar - AI-Powered Penetration Testing CLI
 *
 * Unified entry point for standalone binary compilation.
 * All modules are statically imported so Bun can bundle them.
 */

import packageJson from "../package.json";

// Get command-line arguments
const args = process.argv.slice(2);
const command = args[0];
const subcommand = args[1];
const version = packageJson.version;

function showHelp() {
  console.log("Pensar - AI-Powered Penetration Testing CLI");
  console.log();
  console.log("Usage:");
  console.log("  pensar                    Launch the TUI (Terminal User Interface)");
  console.log("  pensar help               Show this help message");
  console.log("  pensar version            Show version number");
  console.log("  pensar plugin <command>   Manage plugins");
  console.log();
  console.log("Plugin Commands:");
  console.log("  pensar plugin list        List installed plugins");
  console.log("  pensar plugin install <path|package>  Install a plugin");
  console.log("  pensar plugin uninstall <id>          Uninstall a plugin");
  console.log("  pensar plugin enable <id>             Enable a plugin");
  console.log("  pensar plugin disable <id>            Disable a plugin");
  console.log("  pensar plugin info <id>               Show plugin details");
  console.log();
  console.log("Options:");
  console.log("  -h, --help         Show this help message");
  console.log("  -v, --version      Show version number");
  console.log();
}

/**
 * Handle plugin commands
 */
async function handlePluginCommand(subCmd: string, pluginArgs: string[]) {
  const { getPluginManager, initializePlugins } = await import("./core/plugins");
  
  const manager = getPluginManager();
  await manager.initialize();

  switch (subCmd) {
    case "list": {
      const plugins = manager.list();
      if (plugins.length === 0) {
        console.log("No plugins installed.");
      } else {
        console.log("Installed Plugins:\n");
        console.log("ID                          | Name                     | Version | Status  | Type");
        console.log("-".repeat(90));
        for (const entry of plugins) {
          const { id, name, version } = entry.plugin.metadata;
          const type = entry.plugin.type;
          const status = entry.status;
          console.log(
            `${id.padEnd(27)} | ${name.padEnd(24)} | ${version.padEnd(7)} | ${status.padEnd(7)} | ${type}`
          );
        }
      }
      break;
    }

    case "install": {
      const location = pluginArgs[0];
      if (!location) {
        console.error("Error: Please specify a plugin path or package name");
        process.exit(1);
      }

      const isNpm = !location.startsWith(".") && !location.startsWith("/") && !location.includes("\\");
      const source = isNpm ? "npm" : "local";

      console.log(`Installing plugin from ${source}: ${location}`);
      try {
        const plugin = await manager.install({ source, location });
        console.log(`✓ Plugin '${plugin.metadata.name}' (${plugin.metadata.id}) installed successfully`);
      } catch (error: any) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
      }
      break;
    }

    case "uninstall": {
      const pluginId = pluginArgs[0];
      if (!pluginId) {
        console.error("Error: Please specify a plugin ID");
        process.exit(1);
      }

      try {
        await manager.uninstall(pluginId);
        console.log(`✓ Plugin '${pluginId}' uninstalled successfully`);
      } catch (error: any) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
      }
      break;
    }

    case "enable": {
      const pluginId = pluginArgs[0];
      if (!pluginId) {
        console.error("Error: Please specify a plugin ID");
        process.exit(1);
      }

      try {
        manager.enable(pluginId);
        console.log(`✓ Plugin '${pluginId}' enabled`);
      } catch (error: any) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
      }
      break;
    }

    case "disable": {
      const pluginId = pluginArgs[0];
      if (!pluginId) {
        console.error("Error: Please specify a plugin ID");
        process.exit(1);
      }

      try {
        manager.disable(pluginId);
        console.log(`✓ Plugin '${pluginId}' disabled`);
      } catch (error: any) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
      }
      break;
    }

    case "info": {
      const pluginId = pluginArgs[0];
      if (!pluginId) {
        console.error("Error: Please specify a plugin ID");
        process.exit(1);
      }

      const entry = manager.get(pluginId);
      if (!entry) {
        console.error(`Error: Plugin '${pluginId}' not found`);
        process.exit(1);
      }

      const { metadata, type } = entry.plugin;
      console.log(`\nPlugin: ${metadata.name}`);
      console.log("=".repeat(50));
      console.log(`ID:          ${metadata.id}`);
      console.log(`Version:     ${metadata.version}`);
      console.log(`Type:        ${type}`);
      console.log(`Status:      ${entry.status}`);
      console.log(`Description: ${metadata.description}`);
      if (metadata.author) console.log(`Author:      ${metadata.author}`);
      if (metadata.homepage) console.log(`Homepage:    ${metadata.homepage}`);
      if (metadata.license) console.log(`License:     ${metadata.license}`);
      if (metadata.tags?.length) console.log(`Tags:        ${metadata.tags.join(", ")}`);

      // Show type-specific info
      if (type === "tool" && "tools" in entry.plugin) {
        const tools = Object.keys(entry.plugin.tools);
        console.log(`\nTools (${tools.length}):`);
        for (const toolName of tools) {
          const tool = entry.plugin.tools[toolName];
          console.log(`  - ${toolName}: ${tool.description.split("\n")[0]}`);
        }
      } else if (type === "agent" && "agents" in entry.plugin) {
        const agents = Object.keys(entry.plugin.agents);
        console.log(`\nAgents (${agents.length}):`);
        for (const agentName of agents) {
          const agent = entry.plugin.agents[agentName];
          console.log(`  - ${agentName}: ${agent.description.split("\n")[0]}`);
        }
      } else if (type === "model-provider" && "providers" in entry.plugin) {
        const providers = Object.keys(entry.plugin.providers);
        console.log(`\nProviders (${providers.length}):`);
        for (const providerName of providers) {
          const provider = entry.plugin.providers[providerName];
          console.log(`  - ${providerName}: ${provider.models.length} models`);
        }
      }
      break;
    }

    default:
      console.error(`Unknown plugin command: ${subCmd}`);
      console.error("Run 'pensar plugin --help' for usage information");
      process.exit(1);
  }
}

// Route to the appropriate command
if (command === "version" || command === "--version" || command === "-v") {
  console.log(`v${version}`);
} else if (command === "help" || command === "--help" || command === "-h") {
  showHelp();
} else if (command === "plugin") {
  if (!subcommand || subcommand === "help" || subcommand === "--help") {
    console.log("Plugin Management Commands:");
    console.log();
    console.log("  pensar plugin list                    List installed plugins");
    console.log("  pensar plugin install <path|package>  Install a plugin");
    console.log("  pensar plugin uninstall <id>          Uninstall a plugin");
    console.log("  pensar plugin enable <id>             Enable a plugin");
    console.log("  pensar plugin disable <id>            Disable a plugin");
    console.log("  pensar plugin info <id>               Show plugin details");
    console.log();
  } else {
    await handlePluginCommand(subcommand, args.slice(2));
  }
} else if (args.length === 0) {
  // No command specified, run the TUI
  await import("./tui/index.tsx");
} else {
  console.error(`Error: Unknown command '${command}'`);
  console.error();
  console.error("Run 'pensar --help' for usage information");
  process.exit(1);
}
