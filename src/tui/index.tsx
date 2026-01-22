import { createRoot } from "@opentui/react";
import { useState, useEffect } from "react";
import Footer from "./components/footer";
import { CommandProvider } from "./context/command";
import { AgentProvider } from "./context/agent";
import SessionView from "./components/session-view";
import SessionsDisplay from "./components/commands/sessions-display";
import ConfigDialog from "./components/commands/config-dialog";
import ChatApp from "./components/chat";
import HITLWizard from "./components/commands/operator-wizard";
import ProviderManager from "./components/commands/provider-manager";
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
import { DialogProvider, useDialog } from "./context/dialog";
import ShortcutsDialog from "./components/commands/shortcuts-dialog";
import HelpDialog from "./components/commands/help-dialog";
import { KeybindingProvider } from "./context/keybinding";

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
  const [showSessionsDialog, setShowSessionsDialog] = useState(false);
  const [showShortcutsDialog, setShowShortcutsDialog] = useState(false);

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
                    <KeybindingProvider
                     deps={
                      {
                        ctrlCPressTime,
                        setCtrlCPressTime,
                        setShowExitWarning,
                        setInputKey,
                        setShowSessionsDialog,
                        setShowShortcutsDialog,
                        setFocusIndex,
                        navigableItems,                        
                      }
                     }
                    >
                      <AppContent
                        focusIndex={focusIndex}
                        showSessionsDialog={showSessionsDialog}
                        setShowSessionsDialog={setShowSessionsDialog}
                        showShortcutsDialog={showShortcutsDialog}
                        setShowShortcutsDialog={setShowShortcutsDialog}
                        cwd={cwd}
                        setCtrlCPressTime={setCtrlCPressTime}
                        showExitWarning={showExitWarning}
                        setShowExitWarning={setShowExitWarning}
                        inputKey={inputKey}
                        setInputKey={setInputKey}
                      />
                    </KeybindingProvider>
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
  showSessionsDialog,
  setShowSessionsDialog,
  showShortcutsDialog,
  setShowShortcutsDialog,
  cwd,
  setCtrlCPressTime,
  showExitWarning,
  setShowExitWarning,
  inputKey,
  setInputKey,
}: {
  focusIndex: number;
  showSessionsDialog: boolean;
  setShowSessionsDialog: (show: boolean) => void;
  showShortcutsDialog: boolean;
  setShowShortcutsDialog: (show: boolean) => void;
  cwd: string;
  setCtrlCPressTime: (time: number | null) => void;
  showExitWarning: boolean;
  setShowExitWarning: (show: boolean) => void;
  inputKey: number;
  setInputKey: (fn: (prev: number) => number) => void;
}) {

  const route = useRoute();
  const config = useConfig();

  const { refocusPrompt } = useFocus();
  const { setExternalDialogOpen } = useDialog();
  

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

  const handleCloseSessionsDialog = () => {
    setShowSessionsDialog(false);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleCloseShortcutsDialog = () => {
    setShowShortcutsDialog(false);
    setExternalDialogOpen(false);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
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
      <CommandDisplay focusIndex={focusIndex} inputKey={inputKey} />

      {/* Only show footer on non-home routes */}
      <Footer cwd={cwd} showExitWarning={showExitWarning} />

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

      {/* routes to have: home (chat), responsible use, session, global config route */}
      {/* when user either runs command or simply enters message: extract args etc, create session with related config, route to session */}
      {/* on startup, check if responsible use has been agreed, if not route to resp use route */}

        <RouteSwitch condition={routePath}>
          <RouteSwitch.Case when="disclosure">
            <ResponsibleUseDisclosure onAccept={handleAcceptPolicy}/>
          </RouteSwitch.Case>
          <RouteSwitch.Case when="home">
            <ChatApp />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="config">
            <ConfigDialog />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="operator">
            <HITLWizard
              initialTarget={route.data.options?.target}
              initialMode={route.data.options?.mode}
              initialName={route.data.options?.name}
              initialTier={route.data.options?.tier}
              initialHosts={route.data.options?.hosts}
              initialStrict={route.data.options?.strict}
              initialModel={route.data.options?.model}
            />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="providers">
            <ProviderManager />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="help">
            <HelpDialog />
          </RouteSwitch.Case>
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