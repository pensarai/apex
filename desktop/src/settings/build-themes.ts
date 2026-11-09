import { join } from "node:path";
import { getAllThemeNames, getTheme } from "../../../src/tui/theme/registry";
import { registerBuiltinThemes } from "../../../src/tui/theme/themes";

registerBuiltinThemes();
const themes = Object.fromEntries(
  getAllThemeNames().map((id) => {
    const { displayName, colors } = getTheme(id);
    const palette = (mode: "light" | "dark") =>
      Object.fromEntries(
        Object.entries(colors).map(([key, value]) => {
          const color = "dark" in value ? value[mode] : value;
          const [r, g, b, a] = color.toInts();
          return [key, `rgb(${r} ${g} ${b} / ${a / 255})`];
        }),
      );
    return [
      id,
      { name: displayName, light: palette("light"), dark: palette("dark") },
    ];
  }),
);
await Bun.write(
  join(import.meta.dir, "../../node_modules/.cache/apex-themes.json"),
  JSON.stringify(themes),
);
