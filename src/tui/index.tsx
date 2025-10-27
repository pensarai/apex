import { render, useKeyboard, useRenderer } from "@opentui/react";
import {
  convertImageToColoredAscii,
  ColoredAsciiArt,
} from "./components/ascii-art";
import { useState, useEffect } from "react";
import Header from "./components/header";
import Footer from "./components/footer";
import CommandInput from "./command-input";
import { CommandProvider, useCommand } from "./command-provider";
import { AgentProvider } from "./agentProvider";
import HelpDialog from "./components/commands/help-dialog";
import ConfigDialog from "./components/commands/config-dialog";
import PentestAgentDisplay from "./components/commands/pentest-agent-display";
import ThoroughPentestAgentDisplay from "./components/commands/thorough-pentest-agent-display";
import SessionsDisplay from "./components/commands/sessions-display";
import ModelsDisplay from "./components/commands/models-display";
import type { Config } from "../core/config/config";
import { config as _config } from "../core/config";
import AlertDialog from "./components/alert-dialog";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { existsSync } from "fs";
import ResponsibleUseDisclosure from "./components/responsible-use-disclosure";
import { RGBA } from "@opentui/core";
import { RouteProvider, useRoute, type RoutePath } from "./context/route";
import Switch, { createSwitch } from "./components/switch";
import { ConfigProvider, useConfig } from "./context/config";
import DebugPanel from "./components/debug-console";

// Get the directory of the current module
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Find the image path - works both in dev (src/tui) and bundled (build)
function findImagePath(): string {
  // Try bundled path first (build/index.js -> ../pensar.svg)
  const bundledPath = join(__dirname, "..", "pensar.svg");
  if (existsSync(bundledPath)) {
    return bundledPath;
  }

  // Try dev path (src/tui/index.tsx -> ../../pensar.svg)
  const devPath = join(__dirname, "..", "..", "pensar.svg");
  if (existsSync(devPath)) {
    return devPath;
  }

  throw new Error("Could not find pensar.svg");
}

// Configuration
const CONFIG = {
  imagePath: findImagePath(),
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

interface AppProps {
  appConfig: Config;
};

function App(props: AppProps) {
  const { appConfig } = props;
  const [focusIndex, setFocusIndex] = useState(0);
  const [cwd, setCwd] = useState(process.cwd());
  const [ctrlCPressTime, setCtrlCPressTime] = useState<number | null>(null);
  const [showExitWarning, setShowExitWarning] = useState(false);
  const [inputKey, setInputKey] = useState(0); // Force input remount on clear

  const navigableItems = ["command-input"]; // List of items that can be focused

  // useEffect(() => {
  //   async function getConfig() {
  //     const _config = await config.get();
  //     setAppConfig(_config);
  //   }
  //   getConfig();
  // }, []);

  return (
    <ConfigProvider config={appConfig}>
      <RouteProvider>
        <AgentProvider>
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
      </AgentProvider>
      </RouteProvider>
    </ConfigProvider>

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
  const route = useRoute();
  const config = useConfig();

  !config.data.responsibleUseAccepted && route.navigate({
    type: "base",
    path: "disclosure"
  });

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
    if (key.name === "escape") {
      route.navigate({
        type: "base",
        path: "home"
      });
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
    <box
     width="100%"
     height="100%"
     justifyContent="center"
     alignItems="center"
     backgroundColor={"transparent"}
    >
      <ColoredAsciiArt ascii={coloredAscii} />
      <CommandDisplay focusIndex={focusIndex} inputKey={inputKey} />
      {
        config.data.development &&
        <DebugPanel/>
      }
      <Footer cwd={cwd} showExitWarning={showExitWarning} />
    </box>
  );
}

const RouteSwitch = createSwitch<RoutePath>();

function CommandDisplay({
  focusIndex,
  inputKey,
}: {
  focusIndex: number;
  inputKey: number;
}) {

  const route = useRoute();
  const config = useConfig();

  const handleAcceptPolicy = async () => {
    await config.update({ responsibleUseAccepted: true });
    route.navigate({
      type: "base",
      path: "home"
    });
  };

  if(route.data.type === "base") {
    const routePath = route.data.path;
    return (
      <box
        flexDirection="column"
        width="100%"
        maxHeight="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
        flexShrink={1}
        overflow="hidden"
        gap={2}
      >
        <RouteSwitch condition={routePath}>
          <RouteSwitch.Case when="disclosure">
            <ResponsibleUseDisclosure onAccept={handleAcceptPolicy}/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="home">
            <CommandInput focused={focusIndex === 0} inputKey={inputKey}/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="pentest">
            <PentestAgentDisplay/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="thorough">
            <ThoroughPentestAgentDisplay/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="sessions">
            <SessionsDisplay/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="models">
            <ModelsDisplay/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="config">
            <ConfigDialog/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="help">
            <HelpDialog/>
          </RouteSwitch.Case>
          <RouteSwitch.Default>
            <CommandInput focused={focusIndex === 0} inputKey={inputKey}/>
          </RouteSwitch.Default>
        </RouteSwitch>
      </box>
    );
  }

  return null;
}

async function main() {
  const appConfig = await _config.get();
  render(<App appConfig={appConfig}/>, {
    exitOnCtrlC: false, // We'll handle Ctrl+C manually
  });
}

main();

