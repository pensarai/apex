import type { BunPlugin } from "bun";

export const electrobunNativeCompat: BunPlugin = {
  name: "electrobun-native-strings",
  setup(build) {
    build.onLoad(
      {
        filter:
          /electrobun[\\/]dist[^\\/]*[\\/]api[\\/]bun[\\/]proc[\\/]native\.ts$/,
      },
      async ({ path }) => {
        const source = await Bun.file(path).text();
        // Bun 1.4 decodes callback cstrings; Electrobun 1.18 decodes them again.
        return {
          loader: "ts",
          contents: `${source.replaceAll("new CString(", "nativeCString(")}
function nativeCString(value: number | string | CString): string {
  return typeof value === "number" ? new CString(value as Pointer).toString() : String(value);
}
`,
        };
      },
    );
  },
};
