import { render, useKeyboard } from "@opentui/react";
import {
  convertImageToColoredAscii,
  ColoredAsciiArt,
} from "./components /ascii-art";
import { useState, useEffect, useMemo } from "react";
import Header from "./components /header";
import Footer from "./components /footer";
import Autocomplete, {
  type AutocompleteOption,
} from "./components /autocomplete";
import AlertDialog from "./components /alert-dialog";
import { CommandRouter, createDefaultRouter } from "./command-router";

// Configuration
const CONFIG = {
  imagePath: "./pensar.svg",
  scale: 1.0, // Scale the image (0.5 = 50%, 1.0 = 100%, 2.0 = 200%)
  maxWidth: 50, // Optional: maximum width in characters (undefined = no limit)
  aspectRatio: 0.5, // Height adjustment (0.5 = half height, good for most terminals)
  invert: true, // Invert brightness (try true if image looks wrong)
  title: "Pensar Logo", // Optional: title to display
};

// Scale the image with sharp first, then convert to ASCII
const coloredAscii = await convertImageToColoredAscii(
  CONFIG.imagePath,
  CONFIG.scale,
  CONFIG.maxWidth,
  CONFIG.aspectRatio,
  CONFIG.invert
);

console.log(
  `Generated colored ASCII: ${coloredAscii.length} rows x ${
    coloredAscii[0]?.length || 0
  } columns (scale: ${CONFIG.scale * 100}%)`
);

function App() {
  const [command, setCommand] = useState("");
  const [focusIndex, setFocusIndex] = useState(0);
  const [cwd, setCwd] = useState(process.cwd());
  const [ctrlCPressTime, setCtrlCPressTime] = useState<number | null>(null);
  const [showExitWarning, setShowExitWarning] = useState(false);
  const [inputKey, setInputKey] = useState(0); // Force input remount on clear
  const [helpOpen, setHelpOpen] = useState(false);
  const [router] = useState<CommandRouter>(() =>
    createDefaultRouter({
      openHelp: () => setHelpOpen(true),
    })
  );

  const navigableItems = ["command-input"]; // List of items that can be focused

  // Generate autocomplete options from router commands
  const autocompleteOptions = useMemo((): AutocompleteOption[] => {
    const commands = router.getAllCommands();
    const options: AutocompleteOption[] = [];

    for (const cmd of commands) {
      // Add main command
      options.push({
        value: `/${cmd.name}`,
        label: `/${cmd.name}`,
        description: cmd.description,
      });

      // Add aliases
      if (cmd.aliases) {
        for (const alias of cmd.aliases) {
          options.push({
            value: `/${alias}`,
            label: `/${alias}`,
            description: `Alias for /${cmd.name}`,
          });
        }
      }
    }

    return options;
  }, [router]);

  const handleSubmit = async (value: string) => {
    console.log("=== handleSubmit called ===");
    console.log("value:", JSON.stringify(value));
    console.log("type:", typeof value);
    console.log("command state:", JSON.stringify(command));

    const raw = value ?? "";
    const trimmed = raw.trim().toLowerCase();

    console.log("trimmed:", JSON.stringify(trimmed));
    console.log("matches /help?:", trimmed === "/help");

    if (trimmed === "/help") {
      console.log("OPENING HELP DIALOG");
      setHelpOpen(true);
      setCommand("");
      return;
    }

    const handled = await router.execute(raw, {
      openHelp: () => setHelpOpen(true),
    });
    console.log("router handled:", handled);
    setCommand("");
  };

  // Debug: log helpOpen state changes
  useEffect(() => {
    console.log("helpOpen state changed to:", helpOpen);
  }, [helpOpen]);

  // Auto-clear the exit warning after 1 second
  useEffect(() => {
    if (showExitWarning) {
      const timer = setTimeout(() => {
        setShowExitWarning(false);
        setCtrlCPressTime(null);
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [showExitWarning]);

  // Navigation and command hotkey handlers
  useKeyboard((key) => {
    // Ctrl+C should always work, even when dialogs are open
    if (key.ctrl && (key.name === "c" || key.sequence === "\x03")) {
      const now = Date.now();
      const lastPress = ctrlCPressTime;

      if (lastPress && now - lastPress < 1000) {
        process.exit(0);
      } else {
        setCommand("");
        setInputKey((prev) => prev + 1);
        setCtrlCPressTime(now);
        setShowExitWarning(true);
      }
      return;
    }

    // If help dialog is open, let its handler manage Escape; ignore other keys here
    if (helpOpen) return;

    // Tab - Next item
    if (key.name === "tab" && !key.shift) {
      setFocusIndex((prev) => (prev + 1) % navigableItems.length);
      return;
    }

    // Shift+Tab - Previous item
    if (key.name === "tab" && key.shift) {
      setFocusIndex(
        (prev) => (prev - 1 + navigableItems.length) % navigableItems.length
      );
      return;
    }

    // Reset ctrl+c timer on any other key
    if (ctrlCPressTime) {
      setCtrlCPressTime(null);
      setShowExitWarning(false);
    }
  });

  return (
    <>
      <box flexDirection="column" alignItems="center" flexGrow={1} gap={1}>
        <ColoredAsciiArt ascii={coloredAscii} />
        <Header />
        <box
          flexDirection="column"
          justifyContent="center"
          width={60}
          flexGrow={1}
          gap={2}
        >
          <Autocomplete
            key={inputKey}
            label="Command"
            value={command}
            placeholder="Enter a command..."
            focused={focusIndex === 0}
            options={autocompleteOptions}
            onInput={(value) => setCommand(value)}
            onSubmit={handleSubmit}
          />
        </box>
        <Footer cwd={cwd} showExitWarning={showExitWarning} />
      </box>

      <AlertDialog
        title="Help"
        message={
          "Commands:\n - /help: Show this dialog\n\nShortcuts:\n - [TAB] Next  - [SHIFT+TAB] Prev  - [CTRL+C] Clear/Exit"
        }
        open={helpOpen}
        onClose={() => setHelpOpen(false)}
      />
    </>
  );
}

render(<App />, {
  exitOnCtrlC: false, // We'll handle Ctrl+C manually
});
