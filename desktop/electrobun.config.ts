import type { ElectrobunConfig } from "electrobun";
import { version } from "../package.json";

export default {
  app: { name: "Apex", identifier: "ai.pensar.apex", version },
  build: {
    mac: {
      bundleCEF: true,
      chromiumFlags: {
        "remote-debugging-port": "9339",
        "disable-gpu": false,
        "force-renderer-accessibility": true,
      },
    },
    linux: {
      bundleCEF: true,
      chromiumFlags: {
        "remote-debugging-port": "9339",
        "disable-gpu": false,
        "force-renderer-accessibility": true,
      },
    },
    win: {
      bundleCEF: true,
      chromiumFlags: {
        "remote-debugging-port": "9339",
        "disable-gpu": false,
        "force-renderer-accessibility": true,
      },
    },
    bun: { external: ["electron", "chromium-bidi", "camoufox-js", "sharp"] },
    copy: {
      dist: "views/workspace",
      ".cache/cli": "cli",
      "runtime/node_modules": "node_modules",
    },
  },
} satisfies ElectrobunConfig;
