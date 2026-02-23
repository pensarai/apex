import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import Input from "../input";
import { config } from "../../../core/config";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { getPensarApiUrl, getPensarConsoleUrl } from "../../../core/api/constants";

type AuthStep = "prompt" | "input" | "validating" | "success" | "error";

interface ValidationResult {
  workspace: { id: string; name: string; slug: string };
  credits: { balance: number };
}

export default function AuthFlow() {
  const route = useRoute();
  const appConfig = useConfig();
  const [step, setStep] = useState<AuthStep>(
    appConfig.data.pensarAPIKey ? "success" : "prompt"
  );
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [validationResult, setValidationResult] =
    useState<ValidationResult | null>(null);

  const goHome = () => {
    route.navigate({ type: "base", path: "home" });
  };

  const connectUrl = `${getPensarConsoleUrl()}/connect`;

  const openBrowser = () => {
    const url = connectUrl;
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
    setStep("input");
  };

  const validateAndSave = async (key: string) => {
    setStep("validating");
    setError(null);

    try {
      const apiUrl = getPensarApiUrl(appConfig.data);
      const response = await fetch(`${apiUrl}/bedrock/validate`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${key}`,
        },
      });

      if (!response.ok) {
        const body = await response.text();
        let message: string;
        try {
          const parsed = JSON.parse(body);
          message = parsed.error || parsed.message || body;
        } catch {
          message = body;
        }
        throw new Error(message);
      }

      const result = (await response.json()) as ValidationResult;
      setValidationResult(result);

      // Save API key to config
      await config.update({ pensarAPIKey: key });
      appConfig.reload();

      setStep("success");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to validate API key"
      );
      setStep("error");
    }
  };

  const handleDisconnect = async () => {
    await config.update({ pensarAPIKey: null });
    appConfig.reload();
    setValidationResult(null);
    setStep("prompt");
  };

  useKeyboard((key) => {
    if (key.name === "escape") {
      goHome();
      return;
    }

    if (step === "prompt") {
      if (key.name === "return") {
        openBrowser();
      }
    }

    if (step === "error") {
      if (key.name === "return") {
        setStep("input");
      }
    }

    if (step === "success") {
      if (key.name === "return") {
        goHome();
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

      {/* Step: Prompt */}
      {step === "prompt" && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg="white">
              Press <span fg="green">[ENTER]</span> to open Pensar Console in
              your browser and generate an API key.
            </text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              Or visit: {connectUrl}
            </text>
          </box>
          <box marginTop={1}>
            <text fg="gray">
              <span fg="green">[ENTER]</span> Open browser ·{" "}
              <span fg="green">[ESC]</span> Cancel
            </text>
          </box>
        </box>
      )}

      {/* Step: Input */}
      {step === "input" && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg="gray">
              Browser opened. Generate a key and paste it below.
            </text>
          </box>
          <box>
            <Input
              label="API Key"
              description="Your key will be stored locally in ~/.pensar/config.json"
              value={apiKey}
              focused={true}
              onChange={(value) =>
                setApiKey(typeof value === "string" ? value : "")
              }
              onPaste={(event: string | { text: string }) => {
                const cleaned = String(
                  typeof event === "string" ? event : event.text
                );
                setApiKey((prev) => `${prev}${cleaned}`);
              }}
              onSubmit={() => {
                const key = apiKey.trim();
                if (key) {
                  validateAndSave(key);
                }
              }}
            />
          </box>
          <box marginTop={1}>
            <text fg="gray">
              <span fg="green">[ENTER]</span> Validate ·{" "}
              <span fg="green">[ESC]</span> Cancel
            </text>
          </box>
        </box>
      )}

      {/* Step: Validating */}
      {step === "validating" && (
        <box>
          <text fg="yellow">Validating API key...</text>
        </box>
      )}

      {/* Step: Success */}
      {step === "success" && (
        <box flexDirection="column" gap={1}>
          <box>
            <text fg="green">Connected to Pensar Console</text>
          </box>
          {validationResult && (
            <box flexDirection="column">
              <text fg="white">
                Workspace: {validationResult.workspace.name}
              </text>
              <text fg="white">
                Credits: ${validationResult.credits.balance.toFixed(2)}
              </text>
            </box>
          )}
          {!validationResult && appConfig.data.pensarAPIKey && (
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
              <span fg="green">[ENTER]</span> Done ·{" "}
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
            <text fg="red">Validation failed: {error}</text>
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
