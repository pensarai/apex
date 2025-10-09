import { render, useKeyboard } from "@opentui/react";
import {
  convertImageToColoredAscii,
  ColoredAsciiArt,
} from "./components /ascii-art";
import { useState, useEffect } from "react";
import Header from "./components /header";
import Footer from "./components /footer";
import CommandInput from "./command-input";
import AlertDialog from "./components /alert-dialog";
import { CommandProvider, useCommand } from "./command-provider";
import HelpDialog from "./components /help-dialog";
import ConfigDialog from "./components /config-dialog";
import PentestAgentDisplay from "./components /pentest-agent-display";

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
  const [focusIndex, setFocusIndex] = useState(0);
  const [cwd, setCwd] = useState(process.cwd());
  const [ctrlCPressTime, setCtrlCPressTime] = useState<number | null>(null);
  const [showExitWarning, setShowExitWarning] = useState(false);
  const [inputKey, setInputKey] = useState(0); // Force input remount on clear

  const navigableItems = ["command-input"]; // List of items that can be focused

  return (
    <CommandProvider>
      <AppContent
        focusIndex={focusIndex}
        setFocusIndex={setFocusIndex}
        cwd={cwd}
        ctrlCPressTime={ctrlCPressTime}
        setCtrlCPressTime={setCtrlCPressTime}
        showExitWarning={showExitWarning}
        setShowExitWarning={setShowExitWarning}
        inputKey={inputKey}
        setInputKey={setInputKey}
        navigableItems={navigableItems}
      />
    </CommandProvider>
  );
}

function AppContent({
  focusIndex,
  setFocusIndex,
  cwd,
  ctrlCPressTime,
  setCtrlCPressTime,
  showExitWarning,
  setShowExitWarning,
  inputKey,
  setInputKey,
  navigableItems,
}: {
  focusIndex: number;
  setFocusIndex: (fn: (prev: number) => number) => void;
  cwd: string;
  ctrlCPressTime: number | null;
  setCtrlCPressTime: (time: number | null) => void;
  showExitWarning: boolean;
  setShowExitWarning: (show: boolean) => void;
  inputKey: number;
  setInputKey: (fn: (prev: number) => number) => void;
  navigableItems: string[];
}) {
  const { pentestOpen, closePentest } = useCommand();

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
        setInputKey((prev) => prev + 1);
        setCtrlCPressTime(now);
        setShowExitWarning(true);
      }
      return;
    }

    // Escape - Close pentest display if open
    if (key.name === "escape" && pentestOpen) {
      closePentest();
      return;
    }

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
    <CommandProvider>
      <CommandOverlay>
        <box flexDirection="column" alignItems="center" flexGrow={1}>
          <ColoredAsciiArt ascii={coloredAscii} />
          <Header />
          <CommandDisplay focusIndex={focusIndex} inputKey={inputKey} />
          <Footer cwd={cwd} showExitWarning={showExitWarning} />
        </box>
      </CommandOverlay>
    </CommandProvider>
  );
}

function CommandDisplay({
  focusIndex,
  inputKey,
}: {
  focusIndex: number;
  inputKey: number;
}) {
  const { pentestOpen } = useCommand();

  return (
    <box
      flexDirection="column"
      width="100%"
      alignItems="center"
      justifyContent="center"
      flexGrow={1}
      gap={2}
    >
      {!pentestOpen && (
        <CommandInput focused={focusIndex === 0} inputKey={inputKey} />
      )}
      {pentestOpen && <PentestAgentDisplay />}
    </box>
  );
}

function CommandOverlay({ children }: { children: React.ReactNode }) {
  const { helpOpen, closeHelp, configOpen, closeConfig } = useCommand();

  return (
    <>
      {children}
      <HelpDialog helpOpen={helpOpen} closeHelp={closeHelp} />
      <ConfigDialog configOpen={configOpen} closeConfig={closeConfig} />
    </>
  );
}

render(<App />, {
  exitOnCtrlC: false, // We'll handle Ctrl+C manually
});
