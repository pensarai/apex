import type { ElectrobunConfig } from "electrobun";
import { version } from "../package.json";
import { electrobunNativeCompat } from "./electrobun-native-compat";

export default {
  app: { name: "Apex", identifier: "ai.pensar.apex", version },
  build: {
    // Electrobun's bundled Bun 1.3.13 can corrupt memory in native callbacks.
    bunVersion: "1.4.4",
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
    bun: {
      external: ["electron", "chromium-bidi", "camoufox-js", "sharp"],
      plugins: [electrobunNativeCompat],
    },
    copy: {
      dist: "views/workspace",
      ".cache/cli": "cli",
      "runtime/node_modules": "node_modules",
    },
  },
} satisfies ElectrobunConfig;
