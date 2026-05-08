import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import prettierConfig from "eslint-config-prettier";
import unusedImports from "eslint-plugin-unused-imports";
import importX from "eslint-plugin-import-x";

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    plugins: {
      "unused-imports": unusedImports,
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-namespace": "error",
      "@typescript-eslint/no-require-imports": "off",
      "no-unused-vars": "off",
      "unused-imports/no-unused-imports": "error",
      "no-useless-assignment": "off",
      "no-useless-escape": "off",
      "react-hooks/exhaustive-deps": "off",
    },
  },
  // Barrel-file enforcement: forbid reaching past kept module barrels into
  // their internals. The forbid list below is the source of truth for which
  // directories are kept module barriers — adding a new kept barrel means
  // adding a new entry here. See "Barrel files" in AGENTS.md.
  {
    plugins: { "import-x": importX },
    rules: {
      "import-x/no-internal-modules": [
        "error",
        {
          forbid: [
            "**/core/ai/!(index)",
            "**/core/ai/models/!(index)",
            "**/core/agents/offSecAgent/!(index)",
            "**/core/agents/offSecAgent/tools/!(index)",
            "**/core/agents/offSecAgent/tools/email/!(index)",
            "**/core/skills/builtins/!(index)",
            "**/core/report/!(index)",
            "**/core/agents/specialized/whiteboxAttackSurface/!(index)",
            "**/core/agents/specialized/benchmark/!(index)",
            "**/tui/theme/!(index)",
            "**/tui/theme/themes/!(index)",
            "**/tui/keybindings/!(index)",
          ],
        },
      ],
    },
  },
  // Test files are allowed to poke at internals.
  {
    files: ["**/*.test.ts", "**/*.test.tsx", "**/*.test-*.ts"],
    rules: {
      "import-x/no-internal-modules": "off",
    },
  },
  prettierConfig,
  {
    ignores: ["build/**", "dist/**", "node_modules/**", "bin/**"],
  },
);
