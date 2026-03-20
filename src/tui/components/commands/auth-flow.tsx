import { useState, useRef, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { config } from "../../../core/config";
import { useConfig } from "../../context/config";
import {
  getPensarApiUrl,
  getPensarConsoleUrl,
} from "../../../core/api/constants";
import {
  isConnected,
  disconnect,
  startDeviceFlow,
  pollWorkOSToken,
  pollLegacyToken,
  fetchWorkspaces,
  pollForWorkspaceCreation,
  selectWorkspace as selectWorkspaceApi,
} from "../../../core/auth";
import type { DeviceFlowInfo, WorkspaceInfo } from "../../../core/auth";
import { Dialog } from "../../context/dialog";
import { DialogControls } from "../shared/dialog-controls";
import { useTheme } from "../../theme";

interface AuthFlowProps {
  onClose: () => void;
}

type AuthStep =
  | "start"
  | "requesting"
  | "polling"
  | "select-workspace"
  | "creating-workspace"
  | "checking-billing"
  | "success"
  | "error";

export default function AuthFlow({ onClose }: AuthFlowProps) {
  const { colors } = useTheme();
  const appConfig = useConfig();

  const alreadyConnected = isConnected(appConfig.data);
  const hasWorkspace = !!appConfig.data.workspaceId;
  const needsWorkspace =
    alreadyConnected && !hasWorkspace && !!appConfig.data.accessToken;

  const [step, setStep] = useState<AuthStep>(
    needsWorkspace ? "requesting" : alreadyConnected ? "success" : "start",
  );
  const [error, setError] = useState<string | null>(null);
  const [flowInfo, setFlowInfo] = useState<DeviceFlowInfo | null>(null);
  const [workspaces, setWorkspaces] = useState<WorkspaceInfo[]>([]);
  const [selectedWorkspace, setSelectedWorkspace] =
    useState<WorkspaceInfo | null>(null);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [billingUrl, setBillingUrl] = useState<string | null>(null);
  const [balance, setBalance] = useState<number | null>(null);
  const [billingStatus, setBillingStatus] = useState<{
    confirmed: boolean;
    ready: boolean;
    hasPaymentMethod: boolean;
  } | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  const connectedWorkspace = appConfig.data.workspaceSlug
    ? {
        name: appConfig.data.workspaceSlug,
        slug: appConfig.data.workspaceSlug,
      }
    : null;

  const goHome = () => {
    onClose();
  };

  const cleanup = () => {
    abortRef.current?.abort();
    abortRef.current = null;
  };

  useEffect(() => {
    return cleanup;
  }, []);

  const openUrl = (url: string) => {
    try {
      const platform = process.platform;
      if (platform === "darwin") {
        Bun.spawn(["open", url]);
      } else if (platform === "win32") {
        Bun.spawn(["cmd", "/c", "start", url]);
      } else {
        Bun.spawn(["xdg-open", url]);
      }
    } catch {
      // Browser open failed — user will see the fallback URL
    }
  };

  const consoleUrlRef = useRef<string>(getPensarConsoleUrl());

  // ── Step 1: Fetch WorkOS client config and start device flow ──────

  const startFlow = async () => {
    setStep("requesting");
    setError(null);

    cleanup();
    const ac = new AbortController();
    abortRef.current = ac;

    const apiUrl = getPensarApiUrl();

    try {
      // Optionally fetch CLI config to get dynamic consoleUrl
      try {
        const configResponse = await fetch(`${apiUrl}/api/cli/config`);
        if (configResponse.ok) {
          const cliConfig = (await configResponse.json()) as {
            workosClientId: string;
            consoleUrl?: string;
          };
          if (cliConfig.consoleUrl) {
            consoleUrlRef.current = cliConfig.consoleUrl;
          }
        }
      } catch {
        // Config fetch is optional, continue with default consoleUrl
      }

      const info = await startDeviceFlow(apiUrl);
      if (ac.signal.aborted) return;

      setFlowInfo(info);

      if (info.mode === "workos") {
        openUrl(info.deviceInfo.verification_uri_complete);
      } else {
        openUrl(info.deviceInfo.verificationUriComplete);
      }

      setStep("polling");

      // Start polling in the background
      if (info.mode === "workos") {
        handleWorkOSPoll(apiUrl, info, ac);
      } else {
        handleLegacyPoll(apiUrl, info, ac);
      }
    } catch (err) {
      if (ac.signal.aborted) return;
      setError(
        err instanceof Error ? err.message : "Failed to start authorization",
      );
      setStep("error");
    }
  };

  // ── Step 2a: WorkOS token polling ───────────────────────────────────

  const handleWorkOSPoll = async (
    apiUrl: string,
    info: Extract<DeviceFlowInfo, { mode: "workos" }>,
    ac: AbortController,
  ) => {
    try {
      const tokens = await pollWorkOSToken({
        clientId: info.clientId,
        deviceCode: info.deviceInfo.device_code,
        interval: info.deviceInfo.interval,
        expiresIn: info.deviceInfo.expires_in,
        signal: ac.signal,
      });

      if (ac.signal.aborted) return;

      await config.update({
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      });
      await appConfig.reload();

      await handleFetchWorkspaces(apiUrl, tokens.accessToken, ac);
    } catch (err) {
      if (ac.signal.aborted) return;
      setError(err instanceof Error ? err.message : "Authentication failed");
      setStep("error");
    }
  };

  // ── Step 2b: Legacy token polling ───────────────────────────────────

  const handleLegacyPoll = async (
    apiUrl: string,
    info: Extract<DeviceFlowInfo, { mode: "legacy" }>,
    ac: AbortController,
  ) => {
    try {
      const data = await pollLegacyToken({
        apiUrl,
        deviceCode: info.deviceInfo.deviceCode,
        interval: info.deviceInfo.interval,
        expiresIn: info.deviceInfo.expiresIn,
        signal: ac.signal,
      });

      if (ac.signal.aborted) return;

      await config.update({
        pensarAPIKey: data.apiKey!,
        gatewaySigningKey: data.signingKey ?? null,
        gatewayUrl: data.gatewayUrl ?? null,
      });

      if (data.workspace) {
        await config.update({
          workspaceId: data.workspace.id,
          workspaceSlug: data.workspace.slug,
        });
      }
      appConfig.reload();

      setSelectedWorkspace(
        data.workspace
          ? {
              ...data.workspace,
              balance: data.credits?.balance ?? 0,
              hasPaymentMethod: true,
            }
          : null,
      );
      setBalance(data.credits?.balance ?? null);
      setBillingStatus(null);
      setStep("success");
    } catch (err) {
      if (ac.signal.aborted) return;
      setError(err instanceof Error ? err.message : "Authentication failed");
      setStep("error");
    }
  };

  // ── Step 3: Fetch workspaces ────────────────────────────────────────

  const handleFetchWorkspaces = async (
    apiUrl: string,
    accessToken: string,
    ac: AbortController,
  ) => {
    try {
      const wsResult = await fetchWorkspaces(apiUrl, accessToken);
      if (ac.signal.aborted) return;

      // Update consoleUrl if returned by the server
      if (wsResult.consoleUrl) {
        consoleUrlRef.current = wsResult.consoleUrl;
      }

      const ws = wsResult.workspaces;

      if (ws.length === 0) {
        const consoleUrl = consoleUrlRef.current;
        openUrl(`${consoleUrl}/create-workspace?redirect=/credits`);
        setStep("creating-workspace");
        handleWorkspaceCreationPoll(apiUrl, accessToken, ac);
        return;
      }

      if (ws.length === 1) {
        await handleSelectWorkspace(apiUrl, accessToken, ws[0]!, ac);
        return;
      }

      setWorkspaces(ws);
      setSelectedIndex(0);
      setStep("select-workspace");
    } catch (err) {
      if (ac.signal.aborted) return;
      setError(
        err instanceof Error ? err.message : "Failed to fetch workspaces",
      );
      setStep("error");
    }
  };

  // ── Step 3b: Poll for workspace creation ────────────────────────────

  const handleWorkspaceCreationPoll = async (
    apiUrl: string,
    accessToken: string,
    ac: AbortController,
  ) => {
    try {
      const ws = await pollForWorkspaceCreation(apiUrl, accessToken, ac.signal);
      if (ac.signal.aborted) return;

      if (ws.length === 1) {
        await handleSelectWorkspace(apiUrl, accessToken, ws[0]!, ac);
      } else {
        setWorkspaces(ws);
        setSelectedIndex(0);
        setStep("select-workspace");
      }
    } catch (err) {
      if (ac.signal.aborted) return;
      setError(
        err instanceof Error ? err.message : "Workspace creation timed out",
      );
      setStep("error");
    }
  };

  // ── Step 4: Select workspace and check billing ──────────────────────

  const handleSelectWorkspace = async (
    apiUrl: string,
    accessToken: string,
    workspace: WorkspaceInfo,
    ac: AbortController,
  ) => {
    setSelectedWorkspace(workspace);
    setStep("checking-billing");

    try {
      const data = await selectWorkspaceApi(apiUrl, accessToken, workspace.id);
      if (ac.signal.aborted) return;

      await config.update({
        workspaceId: workspace.id,
        workspaceSlug: workspace.slug,
        gatewaySigningKey: data.signingKey ?? null,
        gatewayUrl: data.gatewayUrl ?? null,
      });
      appConfig.reload();

      setBalance(data.billing.balance);
      setBillingStatus({
        confirmed: data.confirmed,
        ready: data.billing.ready,
        hasPaymentMethod: data.billing.hasPaymentMethod,
      });

      if (!data.confirmed && data.billingUrl) {
        setBillingUrl(data.billingUrl);
      }

      setStep("success");
    } catch (err) {
      if (ac.signal.aborted) return;
      setError(
        err instanceof Error ? err.message : "Failed to select workspace",
      );
      setStep("error");
    }
  };

  useEffect(() => {
    if (!needsWorkspace) return;
    const ac = new AbortController();
    abortRef.current = ac;
    const apiUrl = getPensarApiUrl();
    handleFetchWorkspaces(apiUrl, appConfig.data.accessToken!, ac);
  }, []);

  // ── Disconnect ──────────────────────────────────────────────────────

  const handleDisconnect = async () => {
    await disconnect();
    appConfig.reload();
    setFlowInfo(null);
    setSelectedWorkspace(null);
    setBalance(null);
    setBillingUrl(null);
    setBillingStatus(null);
    setStep("start");
  };

  const hasLowBalance = balance !== null && balance < 1;
  const needsBillingSetup =
    billingStatus !== null && !billingStatus.ready && (balance ?? 0) <= 0;
  const showBillingWarning = hasLowBalance || needsBillingSetup;

  const effectiveBillingUrl =
    billingUrl ||
    (selectedWorkspace?.slug
      ? `${consoleUrlRef.current}/${selectedWorkspace.slug}/settings/billing`
      : connectedWorkspace?.slug
        ? `${consoleUrlRef.current}/${connectedWorkspace.slug}/settings/billing`
        : `${consoleUrlRef.current}/credits`);

  const openBillingPage = () => {
    openUrl(effectiveBillingUrl);
    goHome();
  };

  // Derive display values from flowInfo
  const userCode =
    flowInfo?.mode === "workos"
      ? flowInfo.deviceInfo.user_code
      : flowInfo?.mode === "legacy"
        ? flowInfo.deviceInfo.userCode
        : null;

  const verificationUrl =
    flowInfo?.mode === "workos"
      ? flowInfo.deviceInfo.verification_uri_complete
      : flowInfo?.mode === "legacy"
        ? flowInfo.deviceInfo.verificationUriComplete
        : null;

  // ── Keyboard handler ────────────────────────────────────────────────

  useKeyboard((key) => {
    key.preventDefault();

    if (key.name === "escape") {
      cleanup();
      goHome();
      return;
    }

    if (step === "start") {
      if (key.name === "return") {
        startFlow();
      }
    }

    if (step === "select-workspace") {
      if (key.name === "up" && selectedIndex > 0) {
        setSelectedIndex((i) => i - 1);
      }
      if (key.name === "down" && selectedIndex < workspaces.length - 1) {
        setSelectedIndex((i) => i + 1);
      }
      if (key.name === "return" && workspaces[selectedIndex]) {
        const currentConfig = appConfig.data;
        const apiUrl = getPensarApiUrl();
        const accessToken = currentConfig.accessToken!;
        const ac = abortRef.current ?? new AbortController();
        handleSelectWorkspace(
          apiUrl,
          accessToken,
          workspaces[selectedIndex]!,
          ac,
        );
      }
      if (key.raw === "d" || key.raw === "D") {
        handleDisconnect();
      }
    }

    if (step === "error") {
      if (key.name === "return") {
        startFlow();
      }
    }

    if (step === "success") {
      if (key.name === "return") {
        if (showBillingWarning) {
          openBillingPage();
        } else {
          goHome();
        }
      }
      if (key.raw === "d" || key.raw === "D") {
        handleDisconnect();
      }
    }
  });

  // ── Render ──────────────────────────────────────────────────────────

  return (
    <Dialog size="large" onClose={goHome}>
      <box
        flexDirection="column"
        width="100%"
        alignItems="flex-start"
        padding={1}
      >
        {/* Header */}
        <box marginBottom={1}>
          <text fg={colors.primary}>Pensar Console — Managed Inference</text>
        </box>

        <box marginBottom={1}>
          <text fg={colors.textMuted}>
            Connect to Pensar Console for usage-based AI inference.{"\n"}
            No API keys needed — just a Pensar account with credits.
          </text>
        </box>

        {/* Step: Start */}
        {step === "start" && (
          <box flexDirection="column" gap={1}>
            <box>
              <text fg={colors.text}>
                Press <span fg={colors.primary}>[ENTER]</span> to authorize via
                your browser.
              </text>
            </box>
            <box marginTop={1}>
              <DialogControls controls={[
                { key: "Enter", label: "Connect", variant: "primary" },
                { key: "Esc", label: "Cancel" },
              ]} />
            </box>
          </box>
        )}

        {/* Step: Requesting */}
        {step === "requesting" && (
          <box>
            <text fg={colors.warning}>Starting authorization...</text>
          </box>
        )}

        {/* Step: Polling */}
        {step === "polling" && flowInfo && (
          <box flexDirection="column" gap={1}>
            <box>
              <text fg={colors.warning}>
                Waiting for browser authorization...
              </text>
            </box>
            <box marginTop={1}>
              <text fg={colors.text}>
                Your code: <span fg={colors.primary}>{userCode}</span>
              </text>
            </box>
            <box marginTop={1}>
              <text fg={colors.textMuted}>
                If the browser didn't open, visit:{"\n"}
                {verificationUrl}
              </text>
            </box>
            <box marginTop={1}>
              <DialogControls controls={[
                { key: "Esc", label: "Cancel" },
              ]} />
            </box>
          </box>
        )}

        {/* Step: Select Workspace */}
        {step === "select-workspace" && (
          <box flexDirection="column" gap={1}>
            <box>
              <text fg={colors.text}>Select a workspace:</text>
            </box>
            <box flexDirection="column" marginTop={1}>
              {workspaces.map((ws, i) => (
                <box key={ws.id}>
                  <text
                    fg={i === selectedIndex ? colors.primary : colors.textMuted}
                  >
                    {i === selectedIndex ? "▸ " : "  "}
                    {ws.name}{" "}
                    <span fg={colors.textMuted}>
                      ({ws.slug}) — ${ws.balance.toFixed(2)}
                    </span>
                  </text>
                </box>
              ))}
            </box>
            <box marginTop={1}>
              <DialogControls controls={[
                { key: "↑/↓", label: "Navigate" },
                { key: "Enter", label: "Select", variant: "primary" },
                { key: "D", label: "Disconnect", variant: "danger" },
                { key: "Esc", label: "Cancel" },
              ]} />
            </box>
          </box>
        )}

        {/* Step: Creating Workspace */}
        {step === "creating-workspace" && (
          <box flexDirection="column" gap={1}>
            <box>
              <text fg={colors.warning}>
                No workspaces found. Opening browser to create one...
              </text>
            </box>
            <box marginTop={1}>
              <text fg={colors.text}>
                Create a workspace in your browser to get started.
              </text>
            </box>
            <box marginTop={1}>
              <text fg={colors.textMuted}>
                Waiting for workspace creation...
              </text>
            </box>
            <box marginTop={1}>
              <text fg={colors.textMuted}>
                If the browser didn't open, visit:{"\n"}
                {consoleUrlRef.current}/create-workspace
              </text>
            </box>
            <box marginTop={1}>
              <DialogControls controls={[
                { key: "Esc", label: "Cancel" },
              ]} />
            </box>
          </box>
        )}

        {/* Step: Checking Billing */}
        {step === "checking-billing" && (
          <box>
            <text fg={colors.warning}>
              Checking billing for {selectedWorkspace?.name}...
            </text>
          </box>
        )}

        {/* Step: Success */}
        {step === "success" && (
          <box flexDirection="column" gap={1}>
            <box>
              <text fg={colors.success}>Connected to Pensar Console</text>
            </box>
            {(selectedWorkspace || connectedWorkspace) && (
              <box flexDirection="column">
                <text fg={colors.text}>
                  Workspace:{" "}
                  {selectedWorkspace?.name || connectedWorkspace?.name}
                </text>
                {balance !== null && (
                  <text fg={colors.text}>
                    Credits:{" "}
                    <span fg={hasLowBalance ? colors.warning : colors.text}>
                      ${balance.toFixed(2)}
                    </span>
                  </text>
                )}
              </box>
            )}
            {showBillingWarning && (
              <box marginTop={1}>
                <text fg={colors.warning}>
                  {needsBillingSetup
                    ? "Your workspace billing setup is not ready yet."
                    : "Your credit balance is very low. We recommend at least $30 to run"}
                  {"\n"}
                  {needsBillingSetup
                    ? "Press ENTER to open billing and finish setup."
                    : "pentests without interruptions. Press ENTER to open billing."}
                </text>
              </box>
            )}
            {!selectedWorkspace &&
              !connectedWorkspace &&
              appConfig.data.pensarAPIKey && (
                <box>
                  <text fg={colors.textMuted}>
                    Already connected (legacy key saved in config)
                  </text>
                </box>
              )}
            <box marginTop={1}>
              <text fg={colors.textMuted}>
                Pensar models are now available in the model selector.
              </text>
            </box>
            <box marginTop={1}>
              <DialogControls controls={[
                { key: "Enter", label: showBillingWarning ? "Open Billing" : "Done", variant: "primary" },
                { key: "D", label: "Disconnect", variant: "danger" },
                { key: "Esc", label: "Back" },
              ]} />
            </box>
          </box>
        )}

        {/* Step: Error */}
        {step === "error" && (
          <box flexDirection="column" gap={1}>
            <box>
              <text fg={colors.error}>{error}</text>
            </box>
            <box marginTop={1}>
              <DialogControls controls={[
                { key: "Enter", label: "Try Again", variant: "primary" },
                { key: "Esc", label: "Cancel" },
              ]} />
            </box>
          </box>
        )}
      </box>
    </Dialog>
  );
}
