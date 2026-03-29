import { createRoot } from "@opentui/react";
import { useState, useEffect } from "react";
import Footer from "./components/footer";
import { CommandProvider } from "./context/command";
import { AgentProvider } from "./context/agent";
import SessionsDisplay from "./components/commands/sessions-display";
import ChatApp from "./components/chat";
import HITLWizard from "./components/commands/operator-wizard";
import WebWizard from "./components/commands/web-wizard";
import ProviderManager from "./components/commands/provider-manager";
import type { Config } from "../core/config/config";
import type { SessionConfig } from "../core/session";
import { config } from "../core/config";
import { createCliRenderer } from "@opentui/core";
import { ConfigProvider, useConfig } from "./context/config";
import { createSwitch } from "./components/switch";
import {
  type RoutePath,
  type WebCommandOptions,
  RouteProvider,
  useRoute,
} from "./context/route";
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
import { ModelPickerDialog } from "./components/model-picker";
import AuthFlow from "./components/commands/auth-flow";
import CreditsFlow from "./components/commands/credits-flow";
import { KeybindingProvider } from "./context/keybinding";
import OperatorDashboard from "./components/operator-dashboard";
import ThemePicker from "./components/commands/theme-picker";
import SkillsDialog from "./components/commands/skills-dialog";
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
import { TerminalDimensionsProvider } from "./context/dimensions";
import { TerminalFocusHandler } from "./components/terminal-focus-handler";
import { cleanupTerminalFocusMode } from "./terminal-focus";

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
  const [showModelDialog, setShowModelDialog] = useState(false);
  const [showProvidersDialog, setShowProvidersDialog] = useState(false);
  const [showCreditsDialog, setShowCreditsDialog] = useState(false);
  const [showHelpDialog, setShowHelpDialog] = useState(false);
  const [showPentestDialog, setShowPentestDialog] = useState(false);
  const [showSkillsDialog, setShowSkillsDialog] = useState(false);
  const [pendingSkillSlug, setPendingSkillSlug] = useState<string | undefined>(
    undefined,
  );
  const [pendingPentestFlags, setPendingPentestFlags] = useState<
    WebCommandOptions | undefined
  >(undefined);

  const navigableItems = ["command-input"];

  return (
    <ConfigProvider config={appConfig}>
      <SessionProvider>
        <RouteProvider>
          <FocusProvider>
            <TerminalFocusHandler />
            <InputProvider>
              <DialogProvider>
                <AgentProvider>
                  <CommandProvider
                    onOpenSessionsDialog={() => setShowSessionsDialog(true)}
                    onOpenThemeDialog={() => setShowThemeDialog(true)}
                    onOpenModelDialog={() => setShowModelDialog(true)}
                    onOpenProvidersDialog={() => setShowProvidersDialog(true)}
                    onOpenCreditsDialog={() => setShowCreditsDialog(true)}
                    onOpenHelpDialog={() => setShowHelpDialog(true)}
                    onOpenAuthDialog={() => setShowAuthDialog(true)}
                    onOpenPentestDialog={(flags) => {
                      setPendingPentestFlags(flags);
                      setShowPentestDialog(true);
                    }}
                    onOpenSkillsDialog={(slug) => {
                      setPendingSkillSlug(slug);
                      setShowSkillsDialog(true);
                    }}
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
                        showModelDialog={showModelDialog}
                        setShowModelDialog={setShowModelDialog}
                        showProvidersDialog={showProvidersDialog}
                        setShowProvidersDialog={setShowProvidersDialog}
                        showCreditsDialog={showCreditsDialog}
                        setShowCreditsDialog={setShowCreditsDialog}
                        showHelpDialog={showHelpDialog}
                        setShowHelpDialog={setShowHelpDialog}
                        showAuthDialog={showAuthDialog}
                        setShowAuthDialog={setShowAuthDialog}
                        showPentestDialog={showPentestDialog}
                        setShowPentestDialog={setShowPentestDialog}
                        showSkillsDialog={showSkillsDialog}
                        setShowSkillsDialog={setShowSkillsDialog}
                        pendingSkillSlug={pendingSkillSlug}
                        setPendingSkillSlug={setPendingSkillSlug}
                        pendingPentestFlags={pendingPentestFlags}
                        setPendingPentestFlags={setPendingPentestFlags}
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
  showModelDialog,
  setShowModelDialog,
  showProvidersDialog,
  setShowProvidersDialog,
  showCreditsDialog,
  setShowCreditsDialog,
  showHelpDialog,
  setShowHelpDialog,
  showAuthDialog,
  setShowAuthDialog,
  showPentestDialog,
  setShowPentestDialog,
  showSkillsDialog,
  setShowSkillsDialog,
  pendingSkillSlug,
  setPendingSkillSlug,
  pendingPentestFlags,
  setPendingPentestFlags,
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
  showModelDialog: boolean;
  setShowModelDialog: (show: boolean) => void;
  showProvidersDialog: boolean;
  setShowProvidersDialog: (show: boolean) => void;
  showCreditsDialog: boolean;
  setShowCreditsDialog: (show: boolean) => void;
  showHelpDialog: boolean;
  setShowHelpDialog: (show: boolean) => void;
  showAuthDialog: boolean;
  setShowAuthDialog: (show: boolean) => void;
  showPentestDialog: boolean;
  setShowPentestDialog: (show: boolean) => void;
  showSkillsDialog: boolean;
  setShowSkillsDialog: (show: boolean) => void;
  pendingSkillSlug: string | undefined;
  setPendingSkillSlug: (slug: string | undefined) => void;
  pendingPentestFlags: WebCommandOptions | undefined;
  setPendingPentestFlags: (flags: WebCommandOptions | undefined) => void;
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
  const [returnToCredits, setReturnToCredits] = useState(false);

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
      route.data.path !== "auth" &&
      route.data.path !== "providers" &&
      route.data.path !== "disclosure"
    ) {
      route.navigate({ type: "base", path: "auth" });
    }
  }, [config.data.responsibleUseAccepted, route.data]);

  // Track external dialog state so operator input unfocuses while a dialog overlay is open
  const anyExternalDialog =
    showThemeDialog ||
    showModelDialog ||
    showProvidersDialog ||
    showCreditsDialog ||
    showHelpDialog ||
    showAuthDialog ||
    showPentestDialog ||
    showSkillsDialog;

  useEffect(() => {
    if (anyExternalDialog) {
      setExternalDialogOpen(true);
    } else {
      const timer = setTimeout(() => setExternalDialogOpen(false), 0);
      return () => clearTimeout(timer);
    }
  }, [anyExternalDialog]);

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
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleCloseThemeDialog = () => {
    setShowThemeDialog(false);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleCloseModelDialog = () => {
    setShowModelDialog(false);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleCloseProvidersDialog = () => {
    setShowProvidersDialog(false);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleCloseCreditsDialog = () => {
    setShowCreditsDialog(false);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleCloseHelpDialog = () => {
    setShowHelpDialog(false);
    setTimeout(() => {
      setExternalDialogOpen(false);
    }, 0);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleCloseAuthDialog = () => {
    setShowAuthDialog(false);
    if (returnToCredits) {
      setReturnToCredits(false);
      setShowCreditsDialog(true);
    } else {
      setInputKey((prev) => prev + 1);
      refocusPrompt();
    }
  };

  const handleCloseSkillsDialog = () => {
    setShowSkillsDialog(false);
    setPendingSkillSlug(undefined);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleClosePentestDialog = () => {
    setShowPentestDialog(false);
    setPendingPentestFlags(undefined);
    setInputKey((prev) => prev + 1);
    refocusPrompt();
  };

  const handleStartPentest = (
    targets: string[],
    sessionConfig: SessionConfig,
  ) => {
    setShowPentestDialog(false);
    setPendingPentestFlags(undefined);

    const target = targets[0] ?? "";
    const skillArgs: Record<string, string> = {};
    if (target) skillArgs.target = target;
    if (sessionConfig.codebasePath) skillArgs.cwd = sessionConfig.codebasePath;
    const creds = sessionConfig.authCredentials
      ? Array.isArray(sessionConfig.authCredentials)
        ? sessionConfig.authCredentials[0]
        : sessionConfig.authCredentials
      : undefined;
    if (creds?.loginUrl) skillArgs["auth-url"] = creds.loginUrl;
    if (creds?.username) skillArgs["auth-user"] = creds.username;
    if (creds?.password) skillArgs["auth-pass"] = creds.password;
    if (sessionConfig.authenticationInstructions)
      skillArgs["auth-instructions"] = sessionConfig.authenticationInstructions;
    if (sessionConfig.scopeConstraints?.allowedHosts?.length)
      skillArgs.hosts = sessionConfig.scopeConstraints.allowedHosts.join(",");
    if (sessionConfig.scopeConstraints?.allowedPorts?.length)
      skillArgs.ports = sessionConfig.scopeConstraints.allowedPorts
        .map(String)
        .join(",");
    if (sessionConfig.scopeConstraints?.strictScope) skillArgs.strict = "true";

    route.navigate({
      type: "operator",
      nonce: Date.now(),
      initialConfig: {
        requireApproval: false,
        target,
      },
      initialSkill: { slug: "pentest", args: skillArgs },
    });
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
      <CommandDisplay
        focusIndex={focusIndex}
        inputKey={inputKey}
        onOpenAuthDialog={() => setShowAuthDialog(true)}
        onOpenModelDialog={() => setShowModelDialog(true)}
      />

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

      {showModelDialog && (
        <ModelPickerDialog onClose={handleCloseModelDialog} />
      )}

      {showProvidersDialog && (
        <ProviderManager
          onClose={handleCloseProvidersDialog}
          onOpenModelDialog={() => {
            setShowProvidersDialog(false);
            setShowModelDialog(true);
          }}
        />
      )}

      {showCreditsDialog && (
        <CreditsFlow
          onClose={handleCloseCreditsDialog}
          onOpenAuthDialog={() => {
            setShowCreditsDialog(false);
            setReturnToCredits(true);
            setShowAuthDialog(true);
          }}
        />
      )}

      {showHelpDialog && <HelpDialog onClose={handleCloseHelpDialog} />}

      {showSkillsDialog && (
        <SkillsDialog
          onClose={handleCloseSkillsDialog}
          initialSlug={pendingSkillSlug}
        />
      )}

      {showAuthDialog && <AuthFlow onClose={handleCloseAuthDialog} />}

      {showPentestDialog && (
        <WebWizard
          onClose={handleClosePentestDialog}
          onStartPentest={handleStartPentest}
          initialTarget={pendingPentestFlags?.target}
          autoMode={pendingPentestFlags?.auto}
          initialName={pendingPentestFlags?.name}
          initialAuthUrl={pendingPentestFlags?.authUrl}
          initialAuthUser={pendingPentestFlags?.authUser}
          initialAuthPass={pendingPentestFlags?.authPass}
          initialAuthInstructions={pendingPentestFlags?.authInstructions}
          initialHosts={pendingPentestFlags?.hosts}
          initialPorts={pendingPentestFlags?.ports}
          initialStrict={pendingPentestFlags?.strict}
          initialHeadersMode={pendingPentestFlags?.headersMode}
          initialCustomHeaders={pendingPentestFlags?.customHeaders}
          initialModel={pendingPentestFlags?.model}
        />
      )}
    </box>
  );
}

const RouteSwitch = createSwitch<RoutePath>();

function CommandDisplay({
  focusIndex,
  inputKey,
  onOpenAuthDialog,
  onOpenModelDialog,
}: {
  focusIndex: number;
  inputKey: number;
  onOpenAuthDialog: () => void;
  onOpenModelDialog: () => void;
}) {
  const route = useRoute();
  const config = useConfig();
  const { colors } = useTheme();

  const handleAcceptPolicy = async () => {
    await config.update({ responsibleUseAccepted: true });
    route.navigate({
      type: "base",
      path: "auth",
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
          <RouteSwitch.Case when="operator">
            <HITLWizard
              initialTarget={route.data.options?.target}
              initialName={route.data.options?.name}
              initialRequireApproval={route.data.options?.requireApproval}
              initialModel={route.data.options?.model}
            />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="auth">
            <AuthFlow
              hideEsc
              onClose={() => {
                if (hasAnyProviderConfigured(config.data)) {
                  route.navigate({ type: "base", path: "home" });
                } else {
                  route.navigate({ type: "base", path: "providers" });
                }
              }}
            />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="providers">
            <ProviderManager onOpenModelDialog={onOpenModelDialog} />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="models">
            <ModelsDisplay />
          </RouteSwitch.Case>
          <RouteSwitch.Case when="credits">
            <CreditsFlow onOpenAuthDialog={onOpenAuthDialog} />
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
    // All pentest sessions now render via operator dashboard.
    // The dedicated pentest view has been consolidated into the operator view
    // via the pentest skill.
    return <OperatorDashboard sessionId={route.data.sessionId} />;
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
    cleanupTerminalFocusMode();
    renderer.destroy();
    process.exit(0);
  };
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);

  process.on("uncaughtException", (err) => {
    cleanupTerminalFocusMode();
    renderer.destroy();
    console.error("Uncaught exception:", err);
    writeErrorLog(err, "UNCAUGHT");
    process.exit(1);
  });

  process.on("unhandledRejection", (reason) => {
    cleanupTerminalFocusMode();
    renderer.destroy();
    console.error("Unhandled rejection:", reason);
    writeErrorLog(reason, "UNHANDLED_REJECTION");
    process.exit(1);
  });

  createRoot(renderer).render(
    <ThemeProvider initialTheme={themeName} initialMode={mode}>
      <ConsoleThemeSync />
      <TerminalDimensionsProvider>
        <ToastProvider>
          <ErrorBoundary>
            <App appConfig={appConfig} />
          </ErrorBoundary>
          <ToastContainer />
        </ToastProvider>
      </TerminalDimensionsProvider>
    </ThemeProvider>,
  );
}

main();
