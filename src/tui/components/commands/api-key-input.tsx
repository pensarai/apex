import { useKeyboard } from "@opentui/react";
import { useState } from "react";
import Input from "../input";
import { type ProviderType } from "../../../core/providers";
import { useTheme } from "../../theme";

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

  useKeyboard((key) => {
    // Escape - Cancel
    if (key.name === "escape") {
      onCancel();
      return;
    }
  });

  const getProviderInstructions = (provider: ProviderType): string => {
    switch (provider) {
      case "anthropic":
        return "Get your API key from console.anthropic.com";
      case "openai":
        return "Get your API key from platform.openai.com";
      case "openrouter":
        return "Get your API key from openrouter.ai/keys";
      case "bedrock":
        return "Enter your AWS Access Key ID (configure region separately) or AWS Bedrock API Key";
      default:
        return "Enter your API key";
    }
  };

  return (
    <box
      position="absolute"
      top={0}
      left={0}
      zIndex={1001}
      width="100%"
      height="100%"
      justifyContent="center"
      alignItems="center"
      backgroundColor={colors.backgroundOverlay}
    >
      <box
        width={70}
        border={true}
        borderColor={colors.primary}
        backgroundColor={colors.backgroundPanel}
        flexDirection="column"
        padding={2}
      >
        {/* Header */}
        <box
          flexDirection="row"
          justifyContent="space-between"
          marginBottom={2}
        >
          <text fg={colors.primary}>Connect {providerName}</text>
          <text fg={colors.textMuted}>esc</text>
        </box>

        {/* Instructions */}
        <box marginBottom={2}>
          <text fg={colors.textMuted}>{getProviderInstructions(provider)}</text>
        </box>

        {/* Input */}
        <box marginBottom={2}>
          <Input
            label="API Key"
            description="Your API key will be stored locally in ~/.pensar/config.json"
            value={apiKey}
            focused={true}
            onChange={(value) =>
              setApiKey(typeof value === "string" ? value : "")
            }
            onPaste={(event) => {
              const cleaned = String(event.text);
              setApiKey((prev) => `${prev}${cleaned}`);
            }}
            onSubmit={() => {
              const key = apiKey.trim();
              if (key) {
                onSubmit(key);
              }
            }}
          />
        </box>

        {/* Footer help text */}
        <box marginTop={1}>
          <text fg={colors.textMuted}>
            <span fg={colors.primary}>[ENTER]</span> Save ·{" "}
            <span fg={colors.primary}>[ESC]</span> Cancel
          </text>
        </box>
      </box>
    </box>
  );
}
