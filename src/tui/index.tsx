import { createRoot, useRenderer } from "@opentui/react";
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
import { createCliRenderer, RGBA } from "@opentui/core";
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

// Mutable theme colors for non-React overlay rendering (post-process functions).
// Updated by OverlayThemeSync whenever the React theme context changes.
let overlayThemeColors: import("./theme").ThemeColors | null = null;

function OverlayThemeSync() {
  const { colors } = useTheme();
  const renderer = useRenderer();
  useEffect(() => {
    overlayThemeColors = colors;
    // Keep console colors in sync with the active theme
    const c = renderer.console as any;
    const withAlpha = (rgba: import("@opentui/core").RGBA, a: number) =>
      RGBA.fromValues(rgba.r, rgba.g, rgba.b, a);
    c.backgroundColor = withAlpha(colors.backgroundPanel, 0.85);
    c._rgbaTitleBar = withAlpha(colors.backgroundElement, 0.9);
    c._rgbaTitleBarText = colors.text;
    c._rgbaDefault = colors.textMuted;
    c._rgbaInfo = colors.info;
    c._rgbaWarn = colors.warning;
    c._rgbaError = colors.error;
    c._rgbaDebug = colors.textMuted;
    c._rgbaSelection = withAlpha(colors.primary, 0.35);
    c._rgbaCursor = colors.primary;
    c._rgbaCopyButton = colors.primary;
    c.markNeedsRerender();
  }, [colors]);
  return null;
}

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
          <RouteSwitch.Case when="theme">
            <ThemePicker />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="help">
            <HelpDialog />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="models">
            <ModelsDisplay />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="auth">
            <AuthFlow />
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

  // Register built-in themes
  registerBuiltinThemes();

  // Resolve theme and mode from config
  const themeName = appConfig.theme ?? "apex";
  let mode: ColorMode;
  if (appConfig.themeMode === "dark" || appConfig.themeMode === "light") {
    mode = appConfig.themeMode;
  } else {
    mode = await detectTerminalMode();
  }

  // Resolve initial theme colors and seed the module-level ref for overlays
  const themeColors = resolveThemeColors(getTheme(themeName), mode);
  overlayThemeColors = themeColors;

  // Semi-transparent variant of a color for console backgrounds
  const withAlpha = (c: import("@opentui/core").RGBA, a: number) =>
    RGBA.fromValues(c.r, c.g, c.b, a);

  const renderer = await createCliRenderer({
    exitOnCtrlC: false,
    consoleOptions: {
      backgroundColor: withAlpha(themeColors.backgroundPanel, 0.85),
      titleBarColor: withAlpha(themeColors.backgroundElement, 0.9),
      titleBarTextColor: themeColors.text,
      colorDefault: themeColors.textMuted,
      colorInfo: themeColors.info,
      colorWarn: themeColors.warning,
      colorError: themeColors.error,
      colorDebug: themeColors.textMuted,
      selectionColor: withAlpha(themeColors.primary, 0.35),
      cursorColor: themeColors.primary,
      copyButtonColor: themeColors.primary,
    },
  });

  // Copy text to the system clipboard using both OSC 52 and native commands
  let clipboardNotifExpiry = 0;
  const copyToClipboard = (text: string) => {
    renderer.copyToClipboardOSC52(text);
    try {
      const proc = Bun.spawn(
        process.platform === "darwin"
          ? ["pbcopy"]
          : ["xclip", "-selection", "clipboard"],
        { stdin: "pipe" },
      );
      proc.stdin.write(text);
      proc.stdin.end();
    } catch {
      // Clipboard command unavailable
    }
    // Show "Copied to clipboard" notification for 2 seconds
    clipboardNotifExpiry = Date.now() + 2000;
    renderer.requestRender();
    setTimeout(() => renderer.requestRender(), 2010);
  };

  // Draw the "Copied to clipboard" overlay in the top-right corner
  const notifLabel = "Copied to clipboard";
  const notifPadX = 1; // horizontal padding between border and text
  const notifBoxWidth = 1 + notifPadX + notifLabel.length + notifPadX + 1; // border + pad + text + pad + border
  const notifBoxHeight = 3; // border + text + border
  const notifMargin = 1; // equal margin from top and right edges
  renderer.addPostProcessFn((buffer) => {
    if (Date.now() < clipboardNotifExpiry && overlayThemeColors) {
      const c = overlayThemeColors;
      const x = buffer.width - notifBoxWidth - notifMargin;
      const y = notifMargin;
      buffer.fillRect(x, y, notifBoxWidth, notifBoxHeight, c.backgroundElement);
      buffer.drawBox({
        x,
        y,
        width: notifBoxWidth,
        height: notifBoxHeight,
        border: true,
        borderColor: c.border,
        backgroundColor: c.backgroundElement,
        shouldFill: false,
      });
      buffer.drawText(notifLabel, x + 1 + notifPadX, y + 1, c.text, c.backgroundElement);
      renderer.requestRender();
    }
  });

  // Wire up console copy to system clipboard
  renderer.console.onCopySelection = copyToClipboard;

  // Replace the copy button with a static "Select to copy" label
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (renderer.console as any).getCopyButtonLabel = () => "Select to copy";

  // Console: auto-copy on select — when user finishes a mouse selection,
  // immediately copy to clipboard and clear the selection.
  const originalHandleMouse = renderer.console.handleMouse.bind(
    renderer.console,
  );
  renderer.console.handleMouse = (event) => {
    const result = originalHandleMouse(event);
    if (event.type === "up") {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const c = renderer.console as any;
      if (typeof c.hasSelection === "function" && c.hasSelection()) {
        c.triggerCopy();
      }
    }
    return result;
  };

  // App-wide: auto-copy on select — when user finishes selecting text
  // anywhere in the application, copy to clipboard and clear selection.
  renderer.on("selection", (selection: any) => {
    if (selection && !selection.isDragging) {
      const text = selection.getSelectedText();
      if (text) {
        copyToClipboard(text);
      }
      process.nextTick(() => renderer.clearSelection());
    }
  });

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
      <OverlayThemeSync />
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
