import { useState, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";
import { getPensarConsoleUrl } from "../../../core/api";
import { validateGateway } from "../../../core/auth";
import { Dialog } from "../../context/dialog";
import DialogLayout, { type FooterAction } from "../dialog-layout";
import { useTheme } from "../../theme";

type CreditsStep = "loading" | "no-auth" | "display" | "browser-opened";

interface CreditsInfo {
  balance: number;
  workspace: string;
}

interface CreditsFlowProps {
  onClose?: () => void;
  onOpenAuthDialog?: () => void;
}

export default function CreditsFlow({
  onClose,
  onOpenAuthDialog,
}: CreditsFlowProps) {
  const route = useRoute();
  const { colors } = useTheme();
  const [step, setStep] = useState<CreditsStep>("loading");
  const [credits, setCredits] = useState<CreditsInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  const creditsUrl = `${getPensarConsoleUrl()}/credits`;

  const goHome = () => {
    if (onClose) {
      onClose();
    } else {
      route.navigate({ type: "base", path: "home" });
    }
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
    key.preventDefault();

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

  // Build dynamic footer actions per step
  let footerActions: FooterAction[] = [];
  if (step === "no-auth") {
    footerActions = [{ key: "Enter", label: "run /login", variant: "primary" }];
  } else if (step === "display") {
    footerActions = [
      { key: "Enter", label: "open in browser", variant: "primary" },
      { key: "R", label: "refresh" },
    ];
  } else if (step === "browser-opened") {
    footerActions = [
      { key: "Enter", label: "refresh balance", variant: "primary" },
    ];
  }

  return (
    <Dialog size="large" onClose={goHome}>
      <DialogLayout title="Credits" footerActions={footerActions}>
        {/* Loading */}
        {step === "loading" && (
          <box>
            <text fg={colors.warning}>Fetching balance...</text>
          </box>
        )}

        {/* No Auth */}
        {step === "no-auth" && (
          <box flexDirection="column" gap={1}>
            <box>
              <text fg={colors.warning}>Not connected to Pensar Console.</text>
            </box>
            <box>
              <text fg={colors.textMuted}>
                Run <span fg={colors.primary}>/login</span> first to connect
                your account.
              </text>
            </box>
          </box>
        )}

        {/* Display Balance */}
        {step === "display" && (
          <box flexDirection="column" gap={1}>
            {error ? (
              <box>
                <text fg={colors.error}>Error: {error}</text>
              </box>
            ) : credits ? (
              <>
                <box>
                  <text>
                    <span fg={colors.textMuted}>Workspace: </span>
                    <span fg={colors.text}>{credits.workspace}</span>
                  </text>
                </box>
                <box>
                  <text>
                    <span fg={colors.textMuted}>Balance: </span>
                    <span
                      fg={credits.balance < 5 ? colors.warning : colors.success}
                    >
                      ${credits.balance.toFixed(2)}
                    </span>
                  </text>
                </box>
                {credits.balance < 5 && (
                  <box marginTop={1}>
                    <text fg={colors.warning}>
                      Low balance. We recommend at least $30 for uninterrupted
                      pentest runs.
                    </text>
                  </box>
                )}
              </>
            ) : null}

            <box marginTop={1}>
              <text fg={colors.textMuted}>Buy credits at: {creditsUrl}</text>
            </box>
          </box>
        )}

        {/* Browser Opened */}
        {step === "browser-opened" && (
          <box flexDirection="column" gap={1}>
            <box>
              <text fg={colors.success}>
                Browser opened. Purchase credits on the Pensar Console.
              </text>
            </box>
            <box marginTop={1}>
              <text fg={colors.textMuted}>
                Press <span fg={colors.primary}>[ENTER]</span> to refresh your
                balance after purchasing.
              </text>
            </box>
          </box>
        )}
      </DialogLayout>
    </Dialog>
  );
}
