import { defineConfig } from "vitest/config";
import { config } from "dotenv";

// Load environment variables from .env file
config();

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    testTimeout: 120000, // 2 minutes for API calls
    hookTimeout: 120000,
  },
});
