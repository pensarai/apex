import { useState, useRef, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { config } from "../../../core/config";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { getPensarApiUrl, getPensarConsoleUrl } from "../../../core/api/constants";

type AuthStep = "start" | "requesting" | "polling" | "success" | "error";

interface DeviceCodeResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresIn: number;
  interval: number;
}

interface TokenResponse {
  status: "pending" | "complete" | "expired" | "not_found";
  apiKey?: string;
  workspace?: { id: string; name: string; slug: string };
  credits?: { balance: number };
}

export default function AuthFlow() {
  const route = useRoute();
  const appConfig = useConfig();
  const [step, setStep] = useState<AuthStep>(
    appConfig.data.pensarAPIKey ? "success" : "start"
  );
  const [error, setError] = useState<string | null>(null);
  const [deviceInfo, setDeviceInfo] = useState<DeviceCodeResponse | null>(null);
  const [tokenResult, setTokenResult] = useState<TokenResponse | null>(null);
  const pollingRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancelledRef = useRef(false);

  const goHome = () => {
    route.navigate({ type: "base", path: "home" });
  };

  const cleanup = () => {
    cancelledRef.current = true;
    if (pollingRef.current) {
      clearTimeout(pollingRef.current);
      pollingRef.current = null;
    }
  };

  // Cleanup on unmount
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

  const startDeviceFlow = async () => {
    setStep("requesting");
    setError(null);
    cancelledRef.current = false;

    try {
      const apiUrl = getPensarApiUrl(appConfig.data);
      const response = await fetch(`${apiUrl}/auth/device/code`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });

      if (!response.ok) {
        throw new Error("Failed to start device authorization");
      }

      const data = (await response.json()) as DeviceCodeResponse;
      setDeviceInfo(data);

      // Open browser with the complete verification URI
      openUrl(data.verificationUriComplete);

      // Start polling
      setStep("polling");
      pollForToken(apiUrl, data.deviceCode, data.interval, data.expiresIn);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to start authorization"
      );
      setStep("error");
    }
  };

  const pollForToken = (
    apiUrl: string,
    deviceCode: string,
    interval: number,
    expiresIn: number
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

        const data = (await response.json()) as TokenResponse;

        if (cancelledRef.current) return;

        if (data.status === "complete" && data.apiKey) {
          setTokenResult(data);

          // Save API key to config
          await config.update({ pensarAPIKey: data.apiKey });
          appConfig.reload();

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

        // Still pending — poll again
        pollingRef.current = setTimeout(poll, interval * 1000);
      } catch (err) {
        if (cancelledRef.current) return;
        // Network error — retry
        pollingRef.current = setTimeout(poll, interval * 1000);
      }
    };

    pollingRef.current = setTimeout(poll, interval * 1000);
  };

  const handleDisconnect = async () => {
    await config.update({ pensarAPIKey: null });
    appConfig.reload();
    setTokenResult(null);
    setStep("start");
  };

  const hasLowBalance =
    tokenResult !== null &&
    tokenResult.credits !== undefined &&
    tokenResult.credits.balance < 1;

  const creditsUrl = `${getPensarConsoleUrl()}/credits`;

  const openCreditsPage = () => {
    openUrl(creditsUrl);
    goHome();
  };

  useKeyboard((key) => {
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

    if (step === "error") {
      if (key.name === "return") {
        startDeviceFlow();
      }
    }

    if (step === "success") {
      if (key.name === "return") {
        if (hasLowBalance) {
          openCreditsPage();
        } else {
          goHome();
        }
      }
      if (key.raw === "d" || key.raw === "D") {
        handleDisconnect();
      }
    }
  });

  return (
    <box
      flexDirection="column"
      width="100%"
      maxWidth={80}
      alignItems="flex-start"
      padding={1}
    >
      {/* Header */}
      <box marginBottom={1}>
        <text fg="green">
          Pensar Console — Managed Inference
        </text>
      </box>

      <box marginBottom={1}>
        <text fg="gray">
          Connect to Pensar Console for usage-based AI inference.{"\n"}
          No API keys needed — just a Pensar account with credits.
        </text>
      </box>

      {/* Step: Start */}
      {step === "start" && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg="white">
              Press <span fg="green">[ENTER]</span> to authorize via your
              browser.
            </text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              <span fg="green">[ENTER]</span> Connect ·{" "}
              <span fg="green">[ESC]</span> Cancel
            </text>
          </box>
        </box>
      )}

      {/* Step: Requesting */}
      {step === "requesting" && (
        <box>
          <text fg="yellow">Starting authorization...</text>
        </box>
      )}

      {/* Step: Polling */}
      {step === "polling" && deviceInfo && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg="yellow">Waiting for browser authorization...</text>
          </box>
          <box marginTop={1}>
            <text fg="white">
              Your code: <span fg="green">{deviceInfo.userCode}</span>
            </text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              If the browser didn't open, visit:{"\n"}
              {deviceInfo.verificationUriComplete}
            </text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              <span fg="green">[ESC]</span> Cancel
            </text>
          </box>
        </box>
      )}

      {/* Step: Success */}
      {step === "success" && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg="green">Connected to Pensar Console</text>
          </box>
          {tokenResult?.workspace && (
            <box flexDirection="column">
              <text fg="white">
                Workspace: {tokenResult.workspace.name}
              </text>
              <text fg="white">
                Credits:{" "}
                <span fg={hasLowBalance ? "yellow" : "white"}>
                  ${(tokenResult.credits?.balance ?? 0).toFixed(2)}
                </span>
              </text>
            </box>
          )}
          {hasLowBalance && (
            <box marginTop={1}>
              <text fg="yellow">
                Your credit balance is very low. We recommend at least $30 to run{"\n"}
                pentests without interruptions. Press ENTER to buy credits.
              </text>
            </box>
          )}
          {!tokenResult && appConfig.data.pensarAPIKey && (
            <box>
              <text fg="gray">Already connected (key saved in config)</text>
            </box>
          )}
          <box marginTop={1}>
            <text fg="gray">
              Pensar models are now available in the model selector.
            </text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              <span fg="green">[ENTER]</span>{" "}
              {hasLowBalance ? "Buy credits" : "Done"} ·{" "}
              <span fg="red">[D]</span> Disconnect ·{" "}
              <span fg="green">[ESC]</span> Back
            </text>
          </box>
        </box>
      )}

      {/* Step: Error */}
      {step === "error" && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg="red">{error}</text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              <span fg="green">[ENTER]</span> Try again ·{" "}
              <span fg="green">[ESC]</span> Cancel
            </text>
          </box>
        </box>
      )}
    </box>
  );
}
