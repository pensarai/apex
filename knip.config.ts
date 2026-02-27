import type { KnipConfig } from "knip";

const config: KnipConfig = {
  entry: [
    "src/tui/index.tsx",
    "src/cli.ts",
    "bin/pensar.js",
    "scripts/generate-ascii-art.ts",
    "scripts/compare-results.ts",
    "scripts/generate-report.ts",
    "scripts/run-benchmarks.ts",
    "scripts/watch.ts",
    "scripts/attack-surface.ts",
    "scripts/auth.ts",
    "scripts/blackbox-pentest.ts",
  ],
  project: ["src/**/*.{ts,tsx}", "scripts/**/*.ts", "bin/**/*.js"],
  ignore: ["build/**"],
};

export default config;
