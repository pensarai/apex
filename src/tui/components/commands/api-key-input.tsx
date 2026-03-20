import { useKeyboard } from "@opentui/react";
import { useState } from "react";
import Input from "../input";
import { type ProviderType, verifyApiKey } from "../../../core/providers";
import { useTheme } from "../../theme";
import { Dialog } from "../../context/dialog";
import { DialogControls } from "../shared/dialog-controls";

type VerifyState = "idle" | "verifying" | "error";

interface APIKeyInputProps {
  provider: ProviderType;
  providerName: string;
  onSubmit: (apiKey: string) => void;
  onCancel: () => void;
}

export default function APIKeyInput({
  provider,
  providerName,
  onSubmit,
  onCancel,
}: APIKeyInputProps) {
  const { colors } = useTheme();
  const [apiKey, setApiKey] = useState("");
  const [verifyState, setVerifyState] = useState<VerifyState>("idle");
  const [errorMessage, setErrorMessage] = useState("");

  useKeyboard((key) => {
    if (key.name === "escape") {
      key.preventDefault();
      if (verifyState === "verifying") return;
      onCancel();
      return;
    }
  });

  const handleSubmit = async () => {
    const key = apiKey.trim();
    if (!key || verifyState === "verifying") return;

    setVerifyState("verifying");
    setErrorMessage("");

    const result = await verifyApiKey(provider, key);

    if (result.valid) {
      onSubmit(key);
    } else {
      setVerifyState("error");
      setErrorMessage(result.error ?? "Invalid API key");
    }
  };

  const getProviderInstructions = (provider: ProviderType): string => {
    switch (provider) {
      case "anthropic":
        return "Get your API key from console.anthropic.com";
      case "openai":
        return "Get your API key from platform.openai.com";
      case "google":
        return "Get your API key from aistudio.google.com/apikey";
      case "openrouter":
        return "Get your API key from openrouter.ai/keys";
      case "bedrock":
        return "Enter your AWS Access Key ID (configure region separately) or AWS Bedrock API Key";
      default:
        return "Enter your API key";
    }
  };

  return (
    <Dialog size="large" onClose={onCancel}>
      <box flexDirection="column" padding={1} width="100%">
        {/* Header */}
        <text fg={colors.primary}>Connect {providerName}</text>

        {/* Instructions */}
        <box marginTop={1} marginBottom={1}>
          <text fg={colors.textMuted}>{getProviderInstructions(provider)}</text>
        </box>

        {/* Input */}
        <box marginBottom={1}>
          <Input
            label="API Key"
            description="Your API key will be stored locally in ~/.pensar/config.json"
            value={apiKey}
            focused={verifyState !== "verifying"}
            onChange={(value) =>
              setApiKey(typeof value === "string" ? value : "")
            }
            onPaste={(event) => {
              const cleaned = String(event.text);
              setApiKey((prev) => `${prev}${cleaned}`);
            }}
            onSubmit={handleSubmit}
          />
        </box>

        {/* Verification status */}
        {verifyState === "verifying" && (
          <box marginBottom={1}>
            <text fg={colors.textMuted}>Verifying API key...</text>
          </box>
        )}

        {verifyState === "error" && (
          <box marginBottom={1}>
            <text fg={colors.error}>✗ {errorMessage}</text>
          </box>
        )}

        {/* Footer */}
        <DialogControls
          controls={[{ key: "Enter", label: "Save", variant: "primary" }]}
        />
      </box>
    </Dialog>
  );
}
