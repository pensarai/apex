import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    testTimeout: 120000, // 2 minutes for API calls
    hookTimeout: 120000,
  },
});
