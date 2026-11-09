import type { ElectrobunConfig } from "electrobun";
import { version } from "../package.json";

export default {
  app: { name: "Apex", identifier: "ai.pensar.apex", version },
  build: {
    bun: { external: ["electron", "chromium-bidi", "camoufox-js", "sharp"] },
    copy: {
      dist: "views/workspace",
      ".cache/cli": "cli",
      "runtime/node_modules": "node_modules",
    },
  },
} satisfies ElectrobunConfig;
