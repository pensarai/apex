import { type ColorMode, useTheme } from "../../theme";

const LOGO_ROWS = [
  "   ⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇          ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆   ",
  "⢀⣀⣀⣸⡿⠿⠿⠿⠿⠿⠿⠿⠿⠿⣇⣀⣀⣀    ⣀⣀⣀⣸⠿⠿⠿⠿⠿⠿⠿⠿⠿⢿⣇⣀⣀⡀",
  "⣿⣿⣿⡏          ⢸⣿⣿⣿    ⣿⣿⣿⡇          ⢹⣿⣿⣿",
  "⣿⣿⣿⡇          ⢸⣿⣿⣿⣦⣀⣀⣠⣿⣿⣿⡇          ⢸⣿⣿⣿",
  "⣿⣿⣿⡇          ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇          ⢸⣿⣿⣿",
  "⣿⣿⣿⡇          ⢸⣿⣿⣿⠟⠛⠛⠻⣿⣿⣿⡇          ⢸⣿⣿⣿",
  "⣿⣿⣿⡇          ⢸⣿⣿⣿⡀   ⣿⣿⣿⡇          ⢸⣿⣿⣿",
  "⠉⠉⠉⢹⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⡞⠉⠉⠉    ⠉⠉⠉⢳⣶⣶⣶⣶⣶⣶⣶⣶⣶⣶⡏⠉⠉⠉",
  "   ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇          ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇   ",
  "      ⠈⢹⣿⣿⣿⠁                ⠈⣿⣿⣿⡏⠁      ",
  "      ⢀⣸⣿⣿⣿⡀                ⢀⣿⣿⣿⣇⡀      ",
  "   ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇          ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇   ",
  "⣀⣀⣀⣸⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⢧⣀⣀⣀    ⣀⣀⣀⡼⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⣇⣀⣀⣀",
  "⣿⣿⣿⡇          ⢸⣿⣿⣿⠁   ⣿⣿⣿⡇          ⢸⣿⣿⣿",
  "⣿⣿⣿⡇          ⢸⣿⣿⣿⣦⣤⣤⣴⣿⣿⣿⡇          ⢸⣿⣿⣿",
  "⣿⣿⣿⡇          ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇          ⢸⣿⣿⣿",
  "⣿⣿⣿⡇          ⢸⣿⣿⣿⠟⠉⠉⠻⣿⣿⣿⡇          ⢸⣿⣿⣿",
  "⣿⣿⣿⣇          ⢸⣿⣿⣿    ⣿⣿⣿⡇          ⣸⣿⣿⣿",
  "⠈⠉⠉⢹⣷⣶⣶⣶⣶⣶⣶⣶⣶⣶⡏⠉⠉⠉    ⠉⠉⠉⢹⣶⣶⣶⣶⣶⣶⣶⣶⣶⣾⡏⠉⠉⠁",
  "   ⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇          ⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇   ",
];
export const WELCOME_LOGO_WIDTH = LOGO_ROWS[0].length;
export const WELCOME_LOGO_HEIGHT = LOGO_ROWS.length;
const LOGO_SHADES: Record<ColorMode, string[]> = {
  dark: ["#989898", "#707070", "#505050"],
  light: ["#606060", "#808080", "#a0a0a0"],
};
const LOGO_RUNS = LOGO_ROWS.flatMap((row, y) => {
  const runs = ["", "", ""];
  for (let x = 0; x < row.length; x++) {
    const shade = Math.min(
      2,
      Math.floor(
        (x / (WELCOME_LOGO_WIDTH - 1) + y / (WELCOME_LOGO_HEIGHT - 1)) * 1.5,
      ),
    );
    runs[shade] += row[x];
  }
  return runs.map((text, shade) => ({
    id: `${y}-${shade}`,
    shade,
    text: text + (shade === 2 && y < WELCOME_LOGO_HEIGHT - 1 ? "\n" : ""),
  }));
});

export function WelcomeLogo({ top }: { top: number }) {
  const { mode } = useTheme();
  const shades = LOGO_SHADES[mode];

  return (
    <box
      position="absolute"
      top={top}
      bottom={0}
      left={0}
      right={0}
      alignItems="center"
      justifyContent="center"
      overflow="hidden"
    >
      <text
        width={WELCOME_LOGO_WIDTH}
        height={WELCOME_LOGO_HEIGHT}
        flexShrink={0}
        selectable={false}
        overflow="hidden"
      >
        {LOGO_RUNS.map((run) => (
          <span key={run.id} fg={shades[run.shade]}>
            {run.text}
          </span>
        ))}
      </text>
    </box>
  );
}
