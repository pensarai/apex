import { config } from "dotenv";
import { defineConfig } from "vitest/config";

// Load environment variables from .env file
config();

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    testTimeout: 120000, // 2 minutes for API calls
    hookTimeout: 120000,
    pool: "forks",
    // Agent imports make each fork expensive; cap aggregate heap usage.
    maxWorkers: 4,
    minWorkers: 1,
    maxConcurrency: 4,
  },
});
