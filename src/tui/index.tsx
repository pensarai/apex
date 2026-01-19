import { createRoot, useKeyboard, useRenderer } from "@opentui/react";
import { useState, useEffect } from "react";
import Footer from "./components/footer";
import CommandInput from "./command-input";
import { CommandProvider } from "./command-provider";
import { AgentProvider } from "./agentProvider";
import HelpDialog from "./components/commands/help-dialog";
import WebWizard from "./components/commands/web-wizard";
import OperatorWizard from "./components/commands/operator-wizard";
import SessionView from "./components/session-view";
import SessionsDisplay from "./components/commands/sessions-display";
import ConfigDialog from "./components/commands/config-dialog";
import ModelsDisplay from "./components/commands/models-display";
import ProviderManager from "./components/commands/provider-manager";
import ResumeWizard from "./components/commands/resume-wizard";
import ChatApp from "./components/chat";
import type { Config } from "../core/config/config";
import { config } from "../core/config";
import { createCliRenderer } from "@opentui/core";
import { ConfigProvider, useConfig } from "./context/config";
import { createSwitch } from "./components/switch";
import { type RoutePath, RouteProvider, useRoute } from "./context/route";
import { ResponsibleUseDisclosure } from "./components/responsible-use-disclosure";
import { hasAnyProviderConfigured } from "../core/providers";
import { SessionProvider } from "./context/session";
import { InputProvider, useInput } from "./context/input";
import { FocusProvider, useFocus } from "./context/focus";
import { DialogProvider, useDialog } from "./components/dialog";
import ShortcutsDialog from "./components/commands/shortcuts-dialog";

interface AppProps {
  appConfig: Config;
}

function App(props: AppProps) {
  const { appConfig } = props;
  const [focusIndex, setFocusIndex] = useState(0);
  const [cwd, setCwd] = useState(process.cwd());
  const [ctrlCPressTime, setCtrlCPressTime] = useState<number | null>(null);
  const [showExitWarning, setShowExitWarning] = useState(false);
  const [inputKey, setInputKey] = useState(0); // Force input remount on clear

  const navigableItems = ["command-input"]; // List of items that can be focused

  return (
    <ConfigProvider config={appConfig}>
      <SessionProvider>
        <RouteProvider>
          <FocusProvider>
            <InputProvider>
              <DialogProvider>
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
              </DialogProvider>
            </InputProvider>
          </FocusProvider>
        </RouteProvider>
      </SessionProvider>
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
  const renderer = useRenderer();
  const { isInputEmpty } = useInput();
  const { refocusCommandInput } = useFocus();
  const { setExternalDialogOpen } = useDialog();
  const [showCreateSessionDialog, setShowCreateSessionDialog] = useState(false);
  const [showSessionsDialog, setShowSessionsDialog] = useState(false);
  const [showShortcutsDialog, setShowShortcutsDialog] = useState(false);

  // First check: responsible use disclosure
  if (!config.data.responsibleUseAccepted && route.data.type === "base" && route.data.path !== "disclosure") {
    route.navigate({
      type: "base",
      path: "disclosure"
    });
  }

  // Second check: provider configuration (only if not already on providers page)
  if (
    config.data.responsibleUseAccepted &&
    !hasAnyProviderConfigured(config.data) &&
    route.data.type === "base" &&
    route.data.path !== "providers" &&
    route.data.path !== "disclosure"
  ) {
    route.navigate({
      type: "base",
      path: "providers"
    });
  }

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
        // Gracefully cleanup renderer before exit
        renderer.destroy();
        process.exit(0);
      } else {
        setInputKey((prev) => prev + 1);
        setCtrlCPressTime(now);
        setShowExitWarning(true);
      }
      return;
    }

    if(key.ctrl && key.name === "k") {
      renderer.console.toggle();
    }

    // Escape - Return to home from any non-home route
    // Exclude "web", "operator" and "session" routes - they handle their own ESC behavior
    if (key.name === "escape") {
      const isHome = route.data.type === "base" && route.data.path === "home";
      const isWeb = route.data.type === "base" && route.data.path === "web";
      const isOperator = route.data.type === "base" && route.data.path === "operator";
      const isSession = route.data.type === "session";
      if (!isHome && !isWeb && !isOperator && !isSession) {
        route.navigate({
          type: "base",
          path: "home"
        });
        refocusCommandInput();
        return;
      }
    }

    // // Ctrl+N - Create new session (only on home view)
    // if (key.ctrl && key.name === "n" && route.data.type === "base" && route.data.path === "home") {
    //   setShowCreateSessionDialog(true);
    //   return;
    // }

    // // Ctrl+S - Show sessions (only on home view)
    if (key.ctrl && key.name === "s" && route.data.type === "base" && route.data.path === "home") {
      setShowSessionsDialog(true);
      return;
    }

    // ? - Show keyboard shortcuts (when input is empty)
    if (key.sequence === "?" && isInputEmpty) {
      setExternalDialogOpen(true);
      setShowShortcutsDialog(true);
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

  const handleCreateSessionSuccess = (sessionId: string) => {
    setShowCreateSessionDialog(false);
    setInputKey((prev) => prev + 1);
    route.navigate({
      type: "session",
      sessionId: sessionId
    });
  };

  const handleCloseCreateDialog = () => {
    setShowCreateSessionDialog(false);
    setInputKey((prev) => prev + 1);
    refocusCommandInput();
  };

  const handleCloseSessionsDialog = () => {
    setShowSessionsDialog(false);
    setInputKey((prev) => prev + 1);
    refocusCommandInput();
  };

  const handleCloseShortcutsDialog = () => {
    setShowShortcutsDialog(false);
    setExternalDialogOpen(false);
    setInputKey((prev) => prev + 1);
    refocusCommandInput();
  };

  // Check if we're on the home route
  const isHomeRoute = route.data.type === "base" && route.data.path === "home";

  return (
    <box
      flexDirection="column"
      alignItems="center"
      flexGrow={1}
      width="100%"
      maxHeight="100%"
      overflow="hidden"
      backgroundColor={'transparent'}
    >
      {/* Only show large logo on non-home routes */}
      {/* {!isHomeRoute && <ColoredAsciiArt ascii={coloredAscii} />} */}

      <CommandDisplay focusIndex={focusIndex} inputKey={inputKey} />

      {/* Only show footer on non-home routes */}
      <Footer cwd={cwd} showExitWarning={showExitWarning} />

      {/* {showCreateSessionDialog && (
        <CreateSessionDialog
          onClose={handleCloseCreateDialog}
          onSuccess={handleCreateSessionSuccess}
        />
      )} */}

      {showSessionsDialog && (
        <SessionsDisplay onClose={handleCloseSessionsDialog} />
      )}

      {showShortcutsDialog && (
        <ShortcutsDialog open={showShortcutsDialog} onClose={handleCloseShortcutsDialog} />
      )}
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
  const _config = useConfig();

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
        backgroundColor={"transparent"}
      >
        <RouteSwitch condition={routePath}>
          <RouteSwitch.Case when="disclosure">
            <ResponsibleUseDisclosure onAccept={handleAcceptPolicy}/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="home">
            <ChatApp />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="help">
            <HelpDialog/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="web">
            <WebWizard
              initialTarget={route.data.options?.target}
              autoMode={route.data.options?.auto}
              initialName={route.data.options?.name}
              initialAuthUrl={route.data.options?.authUrl}
              initialAuthUser={route.data.options?.authUser}
              initialAuthPass={route.data.options?.authPass}
              initialAuthInstructions={route.data.options?.authInstructions}
              initialHosts={route.data.options?.hosts}
              initialPorts={route.data.options?.ports}
              initialStrict={route.data.options?.strict}
              initialHeadersMode={route.data.options?.headersMode}
              initialCustomHeaders={route.data.options?.customHeaders}
              initialModel={route.data.options?.model}
            />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="operator">
            <OperatorWizard
              initialTarget={(route.data.options as any)?.target}
              initialMode={(route.data.options as any)?.mode}
              initialName={(route.data.options as any)?.name}
              initialTier={(route.data.options as any)?.tier}
              initialAuthUrl={(route.data.options as any)?.authUrl}
              initialAuthUser={(route.data.options as any)?.authUser}
              initialAuthPass={(route.data.options as any)?.authPass}
              initialAuthInstructions={(route.data.options as any)?.authInstructions}
              initialHosts={(route.data.options as any)?.hosts}
              initialStrict={(route.data.options as any)?.strict}
              initialHeadersMode={(route.data.options as any)?.headersMode}
              initialCustomHeaders={(route.data.options as any)?.customHeaders}
              initialModel={(route.data.options as any)?.model}
            />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="config">
            <ConfigDialog />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="models">
            <ModelsDisplay />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="providers">
            <ProviderManager />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="resume">
            <ResumeWizard />
          </RouteSwitch.Case>
          <RouteSwitch.Default>
            <CommandInput focused={focusIndex === 0} inputKey={inputKey}/>
          </RouteSwitch.Default>
        </RouteSwitch>
      </box>
    );
  }

  // Session route - render SessionView which handles pentest execution
  if(route.data.type === "session") {
    return <SessionView sessionId={route.data.sessionId} isResume={route.data.isResume} />;
  }

  return null;
}

async function main() {
  const appConfig = await config.get();
  const renderer = await createCliRenderer({ exitOnCtrlC: false });

  // Graceful shutdown handler
  const cleanup = () => {
    renderer.destroy();
    process.exit(0);
  };

  // Handle process signals for graceful shutdown
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);

  // Handle uncaught errors - cleanup terminal before crash
  process.on("uncaughtException", (err) => {
    renderer.destroy();
    console.error("Uncaught exception:", err);
    process.exit(1);
  });

  process.on("unhandledRejection", (reason) => {
    renderer.destroy();
    console.error("Unhandled rejection:", reason);
    process.exit(1);
  });

  createRoot(renderer)
    .render(<App appConfig={appConfig} />);
}

main();