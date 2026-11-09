import tailwind from "@tailwindcss/vite";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  plugins: [tailwind()],
  esbuild: { jsx: "automatic", jsxImportSource: "react" },
  build: { target: "es2022" },
});
