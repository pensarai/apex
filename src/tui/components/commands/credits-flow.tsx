import { useState, useEffect } from "react";
import { execSync } from "child_process";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import {
  getPensarApiUrl,
  getPensarConsoleUrl,
} from "../../../core/api/constants";
import { ensureValidToken } from "../../../core/api/tokenRefresh";

type CreditsStep = "loading" | "no-auth" | "display" | "browser-opened";

interface CreditsInfo {
  balance: number;
  workspace: string;
}

export default function CreditsFlow() {
  const route = useRoute();
  const appConfig = useConfig();
  const [step, setStep] = useState<CreditsStep>("loading");
  const [credits, setCredits] = useState<CreditsInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  const creditsUrl = `${getPensarConsoleUrl()}/credits`;

  const goHome = () => {
    route.navigate({ type: "base", path: "home" });
  };

  const openBrowser = () => {
    const url = creditsUrl;
    try {
      const platform = process.platform;
      if (platform === "darwin") {
        execSync(`open ${JSON.stringify(url)}`);
      } else if (platform === "win32") {
        execSync(`start ${JSON.stringify(url)}`);
      } else {
        execSync(`xdg-open ${JSON.stringify(url)}`);
      }
    } catch {
      // Browser open failed — user will see the fallback URL
    }
    setStep("browser-opened");
  };

  const fetchBalance = async () => {
    const tokenResult = await ensureValidToken({
      accessToken: appConfig.data.accessToken,
      refreshToken: appConfig.data.refreshToken,
      pensarAPIKey: appConfig.data.pensarAPIKey,
      pensarApiUrl: appConfig.data.pensarApiUrl,
    });
    if (!tokenResult) {
      setStep("no-auth");
      return;
    }

    setStep("loading");
    setError(null);

    try {
      const apiUrl = getPensarApiUrl(appConfig.data);
      const headers: Record<string, string> = {
        Authorization: `Bearer ${tokenResult.token}`,
      };
      // WorkOS auth requires X-Workspace-Id header
      if (tokenResult.type === "workos" && appConfig.data.workspaceId) {
        headers["X-Workspace-Id"] = appConfig.data.workspaceId;
      }
      const response = await fetch(`${apiUrl}/bedrock/validate`, {
        method: "GET",
        headers,
      });

      if (!response.ok) {
        throw new Error("Failed to fetch balance");
      }

      const result = (await response.json()) as {
        workspace: { name: string };
        credits: { balance: number };
      };

      setCredits({
        balance: result.credits.balance,
        workspace: result.workspace.name,
      });
      setStep("display");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch balance");
      setStep("display");
    }
  };

  useEffect(() => {
    fetchBalance();
  }, []);

  useKeyboard((key) => {
    if (key.name === "escape") {
      goHome();
      return;
    }

    if (step === "no-auth") {
      if (key.name === "return") {
        route.navigate({ type: "base", path: "auth" });
      }
    }

    if (step === "display") {
      if (key.name === "return") {
        openBrowser();
      }
      if (key.raw === "r" || key.raw === "R") {
        fetchBalance();
      }
    }

    if (step === "browser-opened") {
      if (key.name === "return") {
        fetchBalance();
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
        <text fg="green">Credits</text>
      </box>

      {/* Loading */}
      {step === "loading" && (
        <box>
          <text fg="yellow">Fetching balance...</text>
        </box>
      )}

      {/* No Auth */}
      {step === "no-auth" && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg="yellow">Not connected to Pensar Console.</text>
          </box>
          <box>
            <text fg="gray">
              Run <span fg="green">/auth</span> first to connect your account.
            </text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              <span fg="green">[ENTER]</span> Run /auth ·{" "}
              <span fg="green">[ESC]</span> Back
            </text>
          </box>
        </box>
      )}

      {/* Display Balance */}
      {step === "display" && (
        <box flexDirection="column" gap={1}>
          {error ? (
            <box>
              <text fg="red">Error: {error}</text>
            </box>
          ) : credits ? (
            <>
              <box>
                <text fg="white">Workspace: {credits.workspace}</text>
              </box>
              <box>
                <text fg="white">
                  Balance:{" "}
                  <span fg={credits.balance < 5 ? "yellow" : "green"}>
                    ${credits.balance.toFixed(2)}
                  </span>
                </text>
              </box>
              {credits.balance < 5 && (
                <box marginTop={1}>
                  <text fg="yellow">
                    Low balance. We recommend at least $30 for uninterrupted
                    pentest runs.
                  </text>
                </box>
              )}
            </>
          ) : null}

          <box marginTop={1}>
            <text fg="gray">
              Press <span fg="green">[ENTER]</span> to buy credits in your
              browser.
            </text>
          </box>
          <box>
            <text fg="gray">Or visit: {creditsUrl}</text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              <span fg="green">[ENTER]</span> Open browser ·{" "}
              <span fg="green">[R]</span> Refresh ·{" "}
              <span fg="green">[ESC]</span> Back
            </text>
          </box>
        </box>
      )}

      {/* Browser Opened */}
      {step === "browser-opened" && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg="green">
              Browser opened. Purchase credits on the Pensar Console.
            </text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              Press <span fg="green">[ENTER]</span> to refresh your balance
              after purchasing.
            </text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              <span fg="green">[ENTER]</span> Refresh balance ·{" "}
              <span fg="green">[ESC]</span> Back
            </text>
          </box>
        </box>
      )}
    </box>
  );
}
