import { useState, useRef, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { config } from "../../../core/config";
import { useConfig } from "../../context/config";
import {
  getPensarApiUrl,
  getPensarConsoleUrl,
} from "../../../core/api/constants";
import { Dialog } from "../../context/dialog";
import { useTheme } from "../../theme";

interface AuthFlowProps {
  onClose: () => void;
}

type AuthStep =
  | "start"
  | "requesting"
  | "polling"
  | "select-workspace"
  | "checking-billing"
  | "success"
  | "error";

interface WorkOSDeviceResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

// Legacy device auth types (fallback when new backend isn't deployed yet)
interface LegacyDeviceCodeResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresIn: number;
  interval: number;
}

interface LegacyTokenResponse {
  status: "pending" | "complete" | "expired" | "not_found";
  apiKey?: string;
  workspace?: { id: string; name: string; slug: string };
  credits?: { balance: number };
}

interface WorkspaceInfo {
  id: string;
  name: string;
  slug: string;
  balance: number;
  hasPaymentMethod: boolean;
}

interface SelectWorkspaceResponse {
  confirmed: boolean;
  workspace: { id: string; name: string; slug: string };
  billing: { balance: number; hasPaymentMethod: boolean; ready: boolean };
  billingUrl?: string;
}

export default function AuthFlow({ onClose }: AuthFlowProps) {
  const { colors } = useTheme();
  const appConfig = useConfig();

  // Determine if already connected (WorkOS token or legacy API key)
  const isConnected = !!(
    appConfig.data.accessToken || appConfig.data.pensarAPIKey
  );

  const [step, setStep] = useState<AuthStep>(isConnected ? "success" : "start");
  const [error, setError] = useState<string | null>(null);
  const [authMode, setAuthMode] = useState<"workos" | "legacy" | null>(null);
  const [deviceInfo, setDeviceInfo] = useState<WorkOSDeviceResponse | null>(
    null,
  );
  const [legacyDeviceInfo, setLegacyDeviceInfo] =
    useState<LegacyDeviceCodeResponse | null>(null);
  const [workspaces, setWorkspaces] = useState<WorkspaceInfo[]>([]);
  const [selectedWorkspace, setSelectedWorkspace] =
    useState<WorkspaceInfo | null>(null);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [billingUrl, setBillingUrl] = useState<string | null>(null);
  const [balance, setBalance] = useState<number | null>(null);
  const pollingRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancelledRef = useRef(false);

  // For existing connections, populate workspace info from config
  const connectedWorkspace = appConfig.data.workspaceSlug
    ? { name: appConfig.data.workspaceSlug, slug: appConfig.data.workspaceSlug }
    : null;

  const goHome = () => {
    onClose();
  };

  const cleanup = () => {
    cancelledRef.current = true;
    if (pollingRef.current) {
      clearTimeout(pollingRef.current);
      pollingRef.current = null;
    }
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

  // ── Step 1: Fetch WorkOS client config and start device flow ──────

  const startDeviceFlow = async () => {
    setStep("requesting");
    setError(null);
    cancelledRef.current = false;

    const apiUrl = getPensarApiUrl(appConfig.data);

    // Try new WorkOS flow first, fall back to legacy device auth
    try {
      const configResponse = await fetch(`${apiUrl}/api/cli/config`);
      if (configResponse.ok) {
        const cliConfig = (await configResponse.json()) as {
          workosClientId: string;
        };

        // New WorkOS device authorization flow
        const response = await fetch(
          "https://api.workos.com/user_management/authorize/device",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ client_id: cliConfig.workosClientId }),
          },
        );

        if (response.ok) {
          const data = (await response.json()) as WorkOSDeviceResponse;
          setAuthMode("workos");
          setDeviceInfo(data);
          openUrl(data.verification_uri_complete);
          setStep("polling");
          pollForToken(
            apiUrl,
            cliConfig.workosClientId,
            data.device_code,
            data.interval,
            data.expires_in,
          );
          return;
        }
      }
    } catch {
      // New endpoint not available — fall through to legacy
    }

    // Legacy device auth flow (backward compat)
    try {
      const response = await fetch(`${apiUrl}/auth/device/code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });

      if (!response.ok) {
        throw new Error("Failed to start device authorization");
      }

      const data = (await response.json()) as LegacyDeviceCodeResponse;
      setAuthMode("legacy");
      setLegacyDeviceInfo(data);
      openUrl(data.verificationUriComplete);
      setStep("polling");
      pollForLegacyToken(
        apiUrl,
        data.deviceCode,
        data.interval,
        data.expiresIn,
      );
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to start authorization",
      );
      setStep("error");
    }
  };

  // ── Step 2: Poll WorkOS for token ─────────────────────────────────

  const pollForToken = (
    apiUrl: string,
    clientId: string,
    deviceCode: string,
    interval: number,
    expiresIn: number,
  ) => {
    const deadline = Date.now() + expiresIn * 1000;

    const poll = async () => {
      if (cancelledRef.current) return;

      if (Date.now() > deadline) {
        setError("Authorization timed out. Please try again.");
        setStep("error");
        return;
      }

      try {
        const response = await fetch(
          "https://api.workos.com/user_management/authenticate",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              client_id: clientId,
              grant_type: "urn:ietf:params:oauth:grant-type:device_code",
              device_code: deviceCode,
            }),
          },
        );

        if (cancelledRef.current) return;

        if (response.status === 400) {
          // Authorization pending — poll again
          pollingRef.current = setTimeout(poll, interval * 1000);
          return;
        }

        if (!response.ok) {
          throw new Error("Authentication failed");
        }

        const data = (await response.json()) as {
          access_token: string;
          refresh_token: string;
        };

        // Save tokens and sync React state
        await config.update({
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
        });
        await appConfig.reload();

        // Fetch user's workspaces
        await fetchWorkspaces(apiUrl, data.access_token);
      } catch (err) {
        if (cancelledRef.current) return;
        // Network error — retry
        pollingRef.current = setTimeout(poll, interval * 1000);
      }
    };

    pollingRef.current = setTimeout(poll, interval * 1000);
  };

  // ── Legacy token polling (fallback for old backend) ────────────────

  const pollForLegacyToken = (
    apiUrl: string,
    deviceCode: string,
    interval: number,
    expiresIn: number,
  ) => {
    const deadline = Date.now() + expiresIn * 1000;

    const poll = async () => {
      if (cancelledRef.current) return;

      if (Date.now() > deadline) {
        setError("Authorization timed out. Please try again.");
        setStep("error");
        return;
      }

      try {
        const response = await fetch(`${apiUrl}/auth/device/token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ deviceCode }),
        });

        if (!response.ok) {
          throw new Error("Failed to check authorization status");
        }

        const data = (await response.json()) as LegacyTokenResponse;

        if (cancelledRef.current) return;

        if (data.status === "complete" && data.apiKey) {
          // Save legacy API key
          await config.update({ pensarAPIKey: data.apiKey });
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
          setStep("success");
          return;
        }

        if (data.status === "expired") {
          setError("Authorization expired. Please try again.");
          setStep("error");
          return;
        }

        if (data.status === "not_found") {
          setError("Invalid authorization session. Please try again.");
          setStep("error");
          return;
        }

        pollingRef.current = setTimeout(poll, interval * 1000);
      } catch (err) {
        if (cancelledRef.current) return;
        pollingRef.current = setTimeout(poll, interval * 1000);
      }
    };

    pollingRef.current = setTimeout(poll, interval * 1000);
  };

  // ── Step 3: Fetch workspaces ──────────────────────────────────────

  const fetchWorkspaces = async (apiUrl: string, accessToken: string) => {
    try {
      const response = await fetch(`${apiUrl}/api/cli/workspaces`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      if (!response.ok) {
        throw new Error("Failed to fetch workspaces");
      }

      const data = (await response.json()) as { workspaces: WorkspaceInfo[] };

      if (data.workspaces.length === 0) {
        setError("No workspaces found. Create one at console.pensar.dev");
        setStep("error");
        return;
      }

      if (data.workspaces.length === 1) {
        // Auto-select single workspace
        await selectWorkspace(apiUrl, accessToken, data.workspaces[0]);
        return;
      }

      setWorkspaces(data.workspaces);
      setSelectedIndex(0);
      setStep("select-workspace");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to fetch workspaces",
      );
      setStep("error");
    }
  };

  // ── Step 4: Select workspace and check billing ────────────────────

  const selectWorkspace = async (
    apiUrl: string,
    accessToken: string,
    workspace: WorkspaceInfo,
  ) => {
    setSelectedWorkspace(workspace);
    setStep("checking-billing");

    try {
      const response = await fetch(`${apiUrl}/api/cli/select-workspace`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({ workspaceId: workspace.id }),
      });

      if (!response.ok) {
        throw new Error("Failed to select workspace");
      }

      const data = (await response.json()) as SelectWorkspaceResponse;

      // Save workspace to config
      await config.update({
        workspaceId: workspace.id,
        workspaceSlug: workspace.slug,
      });
      appConfig.reload();

      setBalance(data.billing.balance);

      if (!data.confirmed && data.billingUrl) {
        // Billing not ready — show URL and let user fix it
        setBillingUrl(data.billingUrl);
      }

      setStep("success");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to select workspace",
      );
      setStep("error");
    }
  };

  // ── Disconnect ────────────────────────────────────────────────────

  const handleDisconnect = async () => {
    await config.update({
      pensarAPIKey: null,
      accessToken: null,
      refreshToken: null,
      workspaceId: null,
      workspaceSlug: null,
    });
    appConfig.reload();
    setAuthMode(null);
    setSelectedWorkspace(null);
    setBalance(null);
    setBillingUrl(null);
    setDeviceInfo(null);
    setLegacyDeviceInfo(null);
    setStep("start");
  };

  const hasLowBalance = balance !== null && balance < 1;

  const effectiveBillingUrl =
    billingUrl ||
    (selectedWorkspace?.slug
      ? `${getPensarConsoleUrl()}/${selectedWorkspace.slug}/settings/billing`
      : connectedWorkspace?.slug
        ? `${getPensarConsoleUrl()}/${connectedWorkspace.slug}/settings/billing`
        : `${getPensarConsoleUrl()}/credits`);

  const openBillingPage = () => {
    openUrl(effectiveBillingUrl);
    goHome();
  };

  // ── Keyboard handler ──────────────────────────────────────────────

  useKeyboard((key) => {
    // Modal dialog — consume all keystrokes to prevent leaking to components underneath
    key.preventDefault();

    if (key.name === "escape") {
      cleanup();
      goHome();
      return;
    }

    if (step === "start") {
      if (key.name === "return") {
        startDeviceFlow();
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
        const apiUrl = getPensarApiUrl(currentConfig);
        const accessToken = currentConfig.accessToken!;
        selectWorkspace(apiUrl, accessToken, workspaces[selectedIndex]);
      }
    }

    if (step === "error") {
      if (key.name === "return") {
        startDeviceFlow();
      }
    }

    if (step === "success") {
      if (key.name === "return") {
        if (hasLowBalance || billingUrl) {
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

  // ── Render ────────────────────────────────────────────────────────

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
            <text fg={colors.textMuted}>
              <span fg={colors.primary}>[ENTER]</span> Connect ·{" "}
              <span fg={colors.primary}>[ESC]</span> Cancel
            </text>
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
      {step === "polling" && (deviceInfo || legacyDeviceInfo) && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg={colors.warning}>
              Waiting for browser authorization...
            </text>
          </box>
          <box marginTop={1}>
            <text fg={colors.text}>
              Your code:{" "}
              <span fg={colors.primary}>
                {deviceInfo?.user_code || legacyDeviceInfo?.userCode}
              </span>
            </text>
          </box>
          <box marginTop={1}>
            <text fg={colors.textMuted}>
              If the browser didn't open, visit:{"\n"}
              {deviceInfo?.verification_uri_complete ||
                legacyDeviceInfo?.verificationUriComplete}
            </text>
          </box>
          <box marginTop={1}>
            <text fg={colors.textMuted}>
              <span fg={colors.primary}>[ESC]</span> Cancel
            </text>
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
                <text fg={i === selectedIndex ? colors.primary : colors.textMuted}>
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
            <text fg={colors.textMuted}>
              <span fg={colors.primary}>[↑/↓]</span> Navigate ·{" "}
              <span fg={colors.primary}>[ENTER]</span> Select ·{" "}
              <span fg={colors.primary}>[ESC]</span> Cancel
            </text>
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
                Workspace: {selectedWorkspace?.name || connectedWorkspace?.name}
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
          {(hasLowBalance || billingUrl) && (
            <box marginTop={1}>
              <text fg={colors.warning}>
                {billingUrl
                  ? "Your workspace needs credits to use Apex CLI."
                  : "Your credit balance is very low. We recommend at least $30 to run"}
                {"\n"}
                {billingUrl
                  ? "Press ENTER to open billing and add credits."
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
            <text fg={colors.textMuted}>
              <span fg={colors.primary}>[ENTER]</span>{" "}
              {hasLowBalance || billingUrl ? "Open billing" : "Done"} ·{" "}
              <span fg={colors.error}>[D]</span> Disconnect ·{" "}
              <span fg={colors.primary}>[ESC]</span> Back
            </text>
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
            <text fg={colors.textMuted}>
              <span fg={colors.primary}>[ENTER]</span> Try again ·{" "}
              <span fg={colors.primary}>[ESC]</span> Cancel
            </text>
          </box>
        </box>
      )}
    </box>
    </Dialog>
  );
}
