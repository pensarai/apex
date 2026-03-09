import { createRoot } from "@opentui/react";
import { useState, useEffect } from "react";
import Footer from "./components/footer";
import { CommandProvider } from "./context/command";
import { AgentProvider } from "./context/agent";
import SessionsDisplay from "./components/commands/sessions-display";
import ConfigDialog from "./components/commands/config-dialog";
import ChatApp from "./components/chat";
import HITLWizard from "./components/commands/operator-wizard";
import WebWizard from "./components/commands/web-wizard";
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
import { InputProvider } from "./context/input";
import { FocusProvider, useFocus } from "./context/focus";
import { DialogProvider, useDialog } from "./context/dialog";
import { ToastProvider } from "./context/toast";
import { ToastContainer } from "./components/toast";
import { ErrorBoundary } from "./components/error-boundary";
import { useToast } from "./context/toast";
import { writeErrorLog } from "../core/logger";
import { checkForUpdate } from "../core/installation";
import ShortcutsDialog from "./components/commands/shortcuts-dialog";
import HelpDialog from "./components/commands/help-dialog";
import ModelsDisplay from "./components/commands/models-display";
import AuthFlow from "./components/commands/auth-flow";
import CreditsFlow from "./components/commands/credits-flow";
import { KeybindingProvider } from "./context/keybinding";
import Pentest from "./components/pentest/pentest";
import OperatorDashboard from "./components/operator-dashboard";
import ThemePicker from "./components/commands/theme-picker";
import CreateSkillWizard from "./components/commands/create-skill-wizard";
import {
  ThemeProvider,
  useTheme,
  resolveThemeColors,
  getTheme,
  type ColorMode,
} from "./theme";
import { registerBuiltinThemes } from "./theme/themes";
import { detectTerminalMode } from "./theme/detect-mode";
import {
  overlayThemeRef,
  buildConsoleOptions,
  ConsoleThemeSync,
} from "./console-theme";
import { createClipboardManager } from "./clipboard";
import { setupAutoCopy } from "./auto-copy";

interface AppProps {
  appConfig: Config;
}

function App({ appConfig }: AppProps) {
  const [focusIndex, setFocusIndex] = useState(0);
  const [cwd, setCwd] = useState(process.cwd());
  const [ctrlCPressTime, setCtrlCPressTime] = useState<number | null>(null);
  const [showExitWarning, setShowExitWarning] = useState(false);
  const [inputKey, setInputKey] = useState(0);
  const [showSessionsDialog, setShowSessionsDialog] = useState(false);
  const [showShortcutsDialog, setShowShortcutsDialog] = useState(false);
  const [showThemeDialog, setShowThemeDialog] = useState(false);
  const [showAuthDialog, setShowAuthDialog] = useState(false);

  const navigableItems = ["command-input"];

  return (
    <ConfigProvider config={appConfig}>
      <SessionProvider>
        <RouteProvider>
          <FocusProvider>
            <InputProvider>
              <DialogProvider>
                <AgentProvider>
                  <CommandProvider
                    onOpenSessionsDialog={() => setShowSessionsDialog(true)}
                    onOpenThemeDialog={() => setShowThemeDialog(true)}
                    onOpenAuthDialog={() => setShowAuthDialog(true)}
                  >
                    <KeybindingProvider
                      deps={{
                        ctrlCPressTime,
                        setCtrlCPressTime,
                        setShowExitWarning,
                        setInputKey,
                        setShowSessionsDialog,
                        setShowShortcutsDialog,
                        setFocusIndex,
                        navigableItems,
                      }}
                    >
                      <AppContent
                        focusIndex={focusIndex}
                        showSessionsDialog={showSessionsDialog}
                        setShowSessionsDialog={setShowSessionsDialog}
                        showShortcutsDialog={showShortcutsDialog}
                        setShowShortcutsDialog={setShowShortcutsDialog}
                        showThemeDialog={showThemeDialog}
                        setShowThemeDialog={setShowThemeDialog}
                        showAuthDialog={showAuthDialog}
                        setShowAuthDialog={setShowAuthDialog}
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
  showThemeDialog,
  setShowThemeDialog,
  showAuthDialog,
  setShowAuthDialog,
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
  showThemeDialog: boolean;
  setShowThemeDialog: (show: boolean) => void;
  showAuthDialog: boolean;
  setShowAuthDialog: (show: boolean) => void;
  cwd: string;
  setCtrlCPressTime: (time: number | null) => void;
  showExitWarning: boolean;
  setShowExitWarning: (show: boolean) => void;
  inputKey: number;
  setInputKey: (fn: (prev: number) => number) => void;
}) {
  const route = useRoute();
  const config = useConfig();
  const { colors } = useTheme();
  const { toast } = useToast();

  const { refocusPrompt } = useFocus();
  const { setExternalDialogOpen } = useDialog();

  useEffect(() => {
    checkForUpdate().then(
      ({ updateAvailable, currentVersion, latestVersion }) => {
        if (!updateAvailable) return;
        toast(
          `Update available: v${currentVersion} → v${latestVersion}. Run: pensar upgrade`,
          "warn",
          8000,
        );
      },
    );
  }, []);

  useEffect(() => {
    if (route.data.type !== "base") return;

    if (
      !config.data.responsibleUseAccepted &&
      route.data.path !== "disclosure"
    ) {
      route.navigate({ type: "base", path: "disclosure" });
    } else if (
      config.data.responsibleUseAccepted &&
      !hasAnyProviderConfigured(config.data) &&
      route.data.path !== "providers" &&
      route.data.path !== "disclosure"
    ) {
      route.navigate({ type: "base", path: "providers" });
    }
  }, [config.data.responsibleUseAccepted, route.data]);

  // Track external dialog state for theme/auth dialogs so operator input
  // unfocuses while a dialog overlay is open
  useEffect(() => {
    if (showThemeDialog || showAuthDialog) {
      setExternalDialogOpen(true);
    }
  }, [showThemeDialog, showAuthDialog]);

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
    setTimeout(() => {
      setExternalDialogOpen(false);
    }, 0);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleCloseThemeDialog = () => {
    setShowThemeDialog(false);
    setTimeout(() => {
      setExternalDialogOpen(false);
    }, 0);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleCloseAuthDialog = () => {
    setShowAuthDialog(false);
    setTimeout(() => {
      setExternalDialogOpen(false);
    }, 0);
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
      backgroundColor={colors.background}
    >
      <CommandDisplay focusIndex={focusIndex} inputKey={inputKey} />

      <Footer cwd={cwd} showExitWarning={showExitWarning} />

      {showSessionsDialog && (
        <SessionsDisplay onClose={handleCloseSessionsDialog} />
      )}

      {showShortcutsDialog && (
        <ShortcutsDialog
          open={showShortcutsDialog}
          onClose={handleCloseShortcutsDialog}
        />
      )}

      {showThemeDialog && <ThemePicker onClose={handleCloseThemeDialog} />}

      {showAuthDialog && <AuthFlow onClose={handleCloseAuthDialog} />}
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
  const { colors } = useTheme();

  const handleAcceptPolicy = async () => {
    await config.update({ responsibleUseAccepted: true });
    route.navigate({
      type: "base",
      path: "home",
    });
  };

  if (route.data.type === "base") {
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
        backgroundColor={colors.background}
      >
        {/* routes to have: home (chat), responsible use, session, global config route */}
        {/* when user either runs command or simply enters message: extract args etc, create session with related config, route to session */}
        {/* on startup, check if responsible use has been agreed, if not route to resp use route */}

        <RouteSwitch condition={routePath}>
          <RouteSwitch.Case when="disclosure">
            <ResponsibleUseDisclosure onAccept={handleAcceptPolicy} />
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
              initialName={route.data.options?.name}
              initialRequireApproval={route.data.options?.requireApproval}
              initialModel={route.data.options?.model}
            />
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
          <RouteSwitch.Case when="models">
            <ModelsDisplay />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="providers">
            <ProviderManager />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="help">
            <HelpDialog />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="models">
            <ModelsDisplay />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="credits">
            <CreditsFlow />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="create-skill">
            <CreateSkillWizard />
          </RouteSwitch.Case>
        </RouteSwitch>
      </box>
    );
  }

  // Session route - render SessionView which handles pentest execution
  if (route.data.type === "operator") {
    return (
      <OperatorDashboard
        key={route.data.sessionId ?? route.data.nonce ?? "new"}
        sessionId={route.data.sessionId}
        initialMessage={route.data.initialMessage}
        initialConfig={route.data.initialConfig}
      />
    );
  }

  if (route.data.type === "pentest") {
    // When openAsOperator is set, render operator dashboard instead of pentest
    if (route.data.openAsOperator) {
      return <OperatorDashboard sessionId={route.data.sessionId} />;
    }
    return (
      <Pentest
        sessionId={route.data.sessionId}
        targets={route.data.targets}
        sessionConfig={route.data.sessionConfig}
      />
    );
  }

  return null;
}

async function main() {
  const appConfig = await config.get();

  registerBuiltinThemes();

  const themeName = appConfig.theme ?? "apex";
  let mode: ColorMode;
  if (appConfig.themeMode === "dark" || appConfig.themeMode === "light") {
    mode = appConfig.themeMode;
  } else {
    mode = await detectTerminalMode();
  }

  const themeColors = resolveThemeColors(getTheme(themeName), mode);
  overlayThemeRef.current = themeColors;

  const renderer = await createCliRenderer({
    exitOnCtrlC: false,
    consoleOptions: buildConsoleOptions(themeColors),
  });

  const { copyToClipboard } = createClipboardManager(renderer);
  setupAutoCopy(renderer, copyToClipboard);

  const cleanup = () => {
    renderer.destroy();
    process.exit(0);
  };
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);

  process.on("uncaughtException", (err) => {
    renderer.destroy();
    console.error("Uncaught exception:", err);
    writeErrorLog(err, "UNCAUGHT");
    process.exit(1);
  });

  process.on("unhandledRejection", (reason) => {
    renderer.destroy();
    console.error("Unhandled rejection:", reason);
    writeErrorLog(reason, "UNHANDLED_REJECTION");
    process.exit(1);
  });

  createRoot(renderer).render(
    <ThemeProvider initialTheme={themeName} initialMode={mode}>
      <ConsoleThemeSync />
      <ToastProvider>
        <ErrorBoundary>
          <App appConfig={appConfig} />
        </ErrorBoundary>
        <ToastContainer />
      </ToastProvider>
    </ThemeProvider>,
  );
}

main();
