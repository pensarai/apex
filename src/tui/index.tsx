import { render, useKeyboard } from "@opentui/react";
import { ColoredAsciiArt } from "./components/ascii-art-component";
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
import { config } from "../core/config";
import AlertDialog from "./components/alert-dialog";

// Pre-generated ASCII art (generated at build time with scripts/generate-ascii-art.ts)
// This avoids needing sharp at runtime, which doesn't work in compiled binaries
import generatedAsciiArt from "./generated-ascii-art.json";

// Use the pre-generated ASCII art
const coloredAscii = generatedAsciiArt as {
  char: string;
  r: number;
  g: number;
  b: number;
}[][];

function App() {
  const [appConfig, setAppConfig] = useState<Config | null>(null);
  const [focusIndex, setFocusIndex] = useState(0);
  const [cwd, setCwd] = useState(process.cwd());
  const [ctrlCPressTime, setCtrlCPressTime] = useState<number | null>(null);
  const [showExitWarning, setShowExitWarning] = useState(false);
  const [inputKey, setInputKey] = useState(0); // Force input remount on clear

  const navigableItems = ["command-input"]; // List of items that can be focused

  useEffect(() => {
    async function getConfig() {
      const _config = await config.get();
      setAppConfig(_config);
    }
    getConfig();
  }, []);

  const handleAcceptPolicy = async () => {
    await config.update({ responsibleUseAccepted: true });
    const updatedConfig = await config.get();
    setAppConfig(updatedConfig);
  };

  return (
    <AgentProvider>
      <CommandProvider>
        <ResponsibleUseWarning
          config={appConfig}
          onAccept={handleAcceptPolicy}
        />
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
  );
}

function ResponsibleUseWarning({
  config: appConfig,
  onAccept,
}: {
  config: Config | null;
  onAccept: () => void;
}) {
  if (!appConfig) return null;

  useKeyboard((key) => {
    if (!appConfig || appConfig.responsibleUseAccepted) return;

    // Enter key accepts the policy
    if (key.name === "return" || key.name === "enter") {
      onAccept();
    }
  });

  return (
    <AlertDialog
      disableEscape={true}
      open={!appConfig.responsibleUseAccepted}
      title="⚠️  Responsible Penetration Testing Policy"
      onClose={() => {}}
    >
      <box flexDirection="column" gap={1}>
        <text fg="yellow">IMPORTANT: Read Before Use</text>
        <text fg="white">
          This penetration testing tool is designedfor AUTHORIZED security
          testing only.
        </text>
        <box flexDirection="column" marginBottom={1}>
          <text fg="red">
            You MUST have explicit written permission to test any systems,
            networks, or applications
          </text>
        </box>
        <text fg="white">By accepting, you agree to:</text>
        <box flexDirection="column" marginLeft={2}>
          <text>• Only test systems you own or have authorization</text>
          <text fg="white">
            • Comply with all applicable laws and regulations
          </text>
          <text fg="white">• Use this tool ethically and responsibly</text>
          <text fg="white">• Not cause harm or disruption to services</text>
          <text fg="white">• Document and report findings appropriately</text>
        </box>
        <box flexDirection="column">
          <text fg="red">
            Unauthorized access to computer systems is illegaland may result in
            criminal prosecution.
          </text>
        </box>
        <box>
          <text fg="white">
            Press <span fg="green">ENTER</span> to accept and continue
          </text>
        </box>
      </box>
    </AlertDialog>
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
  const {
    pentestOpen,
    closePentest,
    thoroughPentestOpen,
    closeThoroughPentest,
    sessionsOpen,
    closeSessions,
    modelsOpen,
    closeModels,
  } = useCommand();

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

    // Escape - Close thorough pentest display if open
    if (key.name === "escape" && thoroughPentestOpen) {
      closeThoroughPentest();
      return;
    }

    // Escape - Close sessions display if open
    if (key.name === "escape" && sessionsOpen) {
      closeSessions();
      return;
    }

    // Escape - Close models display if open
    if (key.name === "escape" && modelsOpen) {
      closeModels();
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
        <box
          flexDirection="column"
          alignItems="center"
          flexGrow={1}
          width="100%"
          maxHeight="100%"
          overflow="hidden"
        >
          <ColoredAsciiArt ascii={coloredAscii} />
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
  const {
    pentestOpen,
    thoroughPentestOpen,
    sessionsOpen,
    closeSessions,
    modelsOpen,
    closeModels,
  } = useCommand();

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
      {!pentestOpen && !thoroughPentestOpen && !sessionsOpen && !modelsOpen && (
        <CommandInput focused={focusIndex === 0} inputKey={inputKey} />
      )}
      {pentestOpen && <PentestAgentDisplay />}
      {thoroughPentestOpen && <ThoroughPentestAgentDisplay />}
      {sessionsOpen && <SessionsDisplay closeSessions={closeSessions} />}
      {modelsOpen && <ModelsDisplay closeModels={closeModels} />}
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
