#!/usr/bin/env bun

/**
 * Pensar - AI-Powered Penetration Testing CLI
 *
 * This is the main entry point for the Pensar CLI tool.
 * It launches the OpenTUI-based terminal interface.
 */

import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Path to the main application
const appPath = join(__dirname, "..", "build", "index.js");

// Import and run the application directly with Bun
await import(appPath);
