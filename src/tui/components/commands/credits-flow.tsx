import { useState, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";
import { getPensarConsoleUrl } from "../../../core/api/constants";
import { validateGateway } from "../../../core/auth";

type CreditsStep = "loading" | "no-auth" | "display" | "browser-opened";

interface CreditsInfo {
  balance: number;
  workspace: string;
}

interface CreditsFlowProps {
  onOpenAuthDialog?: () => void;
}

export default function CreditsFlow({ onOpenAuthDialog }: CreditsFlowProps) {
  const route = useRoute();
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
        Bun.spawn(["open", url]);
      } else if (platform === "win32") {
        Bun.spawn(["cmd", "/c", "start", url]);
      } else {
        Bun.spawn(["xdg-open", url]);
      }
    } catch {
      // Browser open failed — user will see the fallback URL
    }
    setStep("browser-opened");
  };

  const fetchBalance = async () => {
    setStep("loading");
    setError(null);

    try {
      const result = await validateGateway();

      if (!result) {
        setStep("no-auth");
        return;
      }

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
        onOpenAuthDialog?.();
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
