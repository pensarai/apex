import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import prettierConfig from "eslint-config-prettier";
import unusedImports from "eslint-plugin-unused-imports";

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
      "no-restricted-imports": "off",
      "@typescript-eslint/no-restricted-imports": [
        "warn",
        {
          patterns: [
            {
              group: [
                "**/specialized/attackSurface/*",
                "**/specialized/authenticationAgent/*",
                "**/specialized/benchmark/*",
                "!**/specialized/benchmark/remote",
                "**/specialized/benchmark/remote/*",
                "**/specialized/codeAgent/*",
                "**/specialized/cvssScorer/*",
                "**/specialized/pentest/*",
                "**/core/benchmark/*",
                "**/core/workflows/*",
                "**/config/config",
                "**/providers/utils",
                "**/providers/types",
                "**/session/loader",
                "**/ai/utils",
                "**/ai/models",
                "**/ai/ai",
                "**/ai/models/*",
                "**/lib/cvss/*",
                "**/tui/session/*",
                "**/components/swarm-dashboard/*",
                "**/components/tools-panel/*",
              ],
              message:
                "Import from the barrel file (directory index) instead of reaching into submodules.",
            },
          ],
        },
      ],
      "no-restricted-syntax": [
        "warn",
        {
          selector: "ImportExpression",
          message:
            "Prefer static imports. Use eslint-disable with a justification for intentional lazy loading.",
        },
      ],
      "no-restricted-exports": [
        "error",
        {
          restrictDefaultExports: {
            direct: true,
            named: true,
            defaultFrom: true,
            namedFrom: true,
            namespaceFrom: true,
          },
        },
      ],
      "unused-imports/no-unused-imports": "error",
      "no-useless-assignment": "off",
      "no-useless-escape": "off",
      "react-hooks/exhaustive-deps": "off",
    },
  },
  prettierConfig,
  {
    ignores: ["build/**", "dist/**", "node_modules/**", "bin/**"],
  },
);
