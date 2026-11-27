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
    build.onLoad(
      {
        filter:
          /electrobun[\\/]dist[^\\/]*[\\/]api[\\/]bun[\\/]preload[\\/]\.generated[\\/]compiled\.ts$/,
      },
      async ({ path }) => {
        const source = await Bun.file(path).text();
        const preload = /^(export const preloadScript = )(".*");$/m;
        if (!preload.test(source)) {
          throw new Error("Could not find the Electrobun webview preload");
        }
        return {
          loader: "ts",
          contents: source.replace(preload, (_, declaration, encoded) => {
            const script: string = JSON.parse(encoded);
            const initialFrame =
              /frame: \{\s*width: rect\.width,\s*height: rect\.height,\s*x: rect\.x,\s*y: rect\.y\s*\}(?=,\s*navigationRules:)/;
            const syncedFrame = /frame: rect,\s*masks: masksJson/;
            if (!initialFrame.test(script) || !syncedFrame.test(script)) {
              throw new Error("Could not find the Electrobun webview bounds");
            }
            // Electrobun 1.18 sends CSS pixels to the Windows CEF native child.
            const patched = script
              .replace(initialFrame, "frame: scaleCefRect(rect, renderer)")
              .replace(
                syncedFrame,
                `frame: scaleCefRect(rect, this.renderer),
          masks: isWindowsCef(this.renderer)
            ? JSON.stringify(JSON.parse(masksJson).map(mask => scaleCefRect(mask, this.renderer)))
            : masksJson`,
              );
            return `${declaration}${JSON.stringify(`(() => {
function isWindowsCef(renderer) {
  return renderer === "cef" && navigator.platform.startsWith("Win");
}
function scaleCefRect(rect, renderer) {
  const scale = isWindowsCef(renderer) ? window.devicePixelRatio : 1;
  return { x: rect.x * scale, y: rect.y * scale, width: rect.width * scale, height: rect.height * scale };
}
${patched}
})();`)};`;
          }),
        };
      },
    );
  },
};
