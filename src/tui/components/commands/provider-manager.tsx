import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { config } from "../../../core/config";
import {
  type ProviderType,
  AVAILABLE_PROVIDERS,
  hasAnyProviderConfigured,
} from "../../../core/providers";
import ProviderSelection from "./provider-selection";
import APIKeyInput from "./api-key-input";
import AuthFlow from "./auth-flow";
import { useTheme } from "../../theme";
import { Dialog } from "../../context/dialog";
import { DialogControls } from "../shared/dialog-controls";

type FlowState = "choosing" | "selecting" | "inputting" | "auth";

interface ProviderManagerProps {
  onClose?: () => void;
  onOpenModelDialog?: () => void;
}

export default function ProviderManager({
  onClose,
  onOpenModelDialog,
}: ProviderManagerProps = {}) {
  const route = useRoute();
  const _config = useConfig();

  const isOnboarding = !hasAnyProviderConfigured(_config.data);
  const [flowState, setFlowState] = useState<FlowState>(
    isOnboarding ? "choosing" : "selecting",
  );
  const [selectedProvider, setSelectedProvider] = useState<ProviderType | null>(
    null,
  );

  const handleProviderSelected = (providerId: ProviderType) => {
    setSelectedProvider(providerId);
    if (providerId === "pensar") {
      setFlowState("auth");
    } else {
      setFlowState("inputting");
    }
  };

  const handleAPIKeySubmit = async (apiKey: string) => {
    if (!selectedProvider) return;

    const configUpdate: Record<string, string> = {};
    switch (selectedProvider) {
      case "anthropic":
        configUpdate.anthropicAPIKey = apiKey;
        break;
      case "openai":
        configUpdate.openAiAPIKey = apiKey;
        break;
      case "google":
        configUpdate.googleAPIKey = apiKey;
        break;
      case "openrouter":
        configUpdate.openRouterAPIKey = apiKey;
        break;
      case "bedrock":
        configUpdate.bedrockAPIKey = apiKey;
        break;
    }

    await config.update(configUpdate);
    await _config.reload();

    if (onOpenModelDialog) {
      // Transition directly to model dialog — skip prompt cleanup
      onOpenModelDialog();
    } else if (onClose) {
      onClose();
    } else {
      route.navigate({ type: "base", path: "home" });
    }
  };

  const handleAPIKeyCancel = () => {
    if (isOnboarding) {
      setFlowState("choosing");
    } else {
      setFlowState("selecting");
    }
    setSelectedProvider(null);
  };

  const handleClose = () => {
    if (onClose) {
      onClose();
    } else {
      route.navigate({ type: "base", path: "home" });
    }
  };

  const handleAuthClose = () => {
    if (isOnboarding) {
      setFlowState("choosing");
    } else {
      handleClose();
    }
  };

  const otherProviders = AVAILABLE_PROVIDERS.filter((p) => p.id !== "pensar");

  const selectedProviderInfo = AVAILABLE_PROVIDERS.find(
    (p) => p.id === selectedProvider,
  );

  return (
    <>
      {flowState === "choosing" && (
        <OnboardingChoice
          onPensarSelected={() => setFlowState("auth")}
          onOtherSelected={() => setFlowState("selecting")}
        />
      )}
      {flowState === "selecting" && (
        <ProviderSelection
          providers={isOnboarding ? otherProviders : undefined}
          onProviderSelected={handleProviderSelected}
          onClose={isOnboarding ? () => setFlowState("choosing") : handleClose}
        />
      )}
      {flowState === "inputting" &&
        selectedProvider &&
        selectedProviderInfo && (
          <APIKeyInput
            provider={selectedProvider}
            providerName={selectedProviderInfo.name}
            onSubmit={handleAPIKeySubmit}
            onCancel={handleAPIKeyCancel}
          />
        )}
      {flowState === "auth" && (
        <AuthFlow onClose={handleAuthClose} hideEsc={isOnboarding} />
      )}
    </>
  );
}

function OnboardingChoice({
  onPensarSelected,
  onOtherSelected,
}: {
  onPensarSelected: () => void;
  onOtherSelected: () => void;
}) {
  const { colors } = useTheme();
  const [highlightedIndex, setHighlightedIndex] = useState(0);

  const choices = [
    {
      label: "Pensar",
      description: "Managed inference — no API keys needed",
      action: onPensarSelected,
    },
    {
      label: "Use other provider",
      description: "Connect with your own API key (Anthropic, OpenAI, etc.)",
      action: onOtherSelected,
    },
  ];

  useKeyboard((key) => {
    key.preventDefault();

    if (key.name === "up") {
      setHighlightedIndex((prev) => (prev > 0 ? prev - 1 : choices.length - 1));
      return;
    }

    if (key.name === "down") {
      setHighlightedIndex((prev) => (prev < choices.length - 1 ? prev + 1 : 0));
      return;
    }

    if (key.name === "return") {
      choices[highlightedIndex].action();
      return;
    }
  });

  return (
    <Dialog size="large" onClose={() => {}} hideEsc>
      <box flexDirection="column" padding={1} width="100%">
        {/* Header */}
        <box>
          <text fg={colors.primary}>Get Started</text>
        </box>

        <box marginTop={1}>
          <text fg={colors.textMuted}>
            Choose how to connect an AI provider.
          </text>
        </box>

        {/* Choices */}
        <box flexDirection="column" gap={1} marginTop={1}>
          {choices.map((choice, index) => {
            const isHighlighted = index === highlightedIndex;
            return (
              <box
                key={choice.label}
                flexDirection="column"
                paddingLeft={1}
                paddingRight={1}
                backgroundColor={
                  isHighlighted ? colors.backgroundSelected : undefined
                }
                onMouseDown={choice.action}
              >
                <text fg={isHighlighted ? colors.primary : colors.text}>
                  {isHighlighted ? "▸ " : "  "}
                  {choice.label}
                </text>
                <text fg={colors.textMuted}>
                  {"    "}
                  {choice.description}
                </text>
              </box>
            );
          })}
        </box>

        {/* Footer */}
        <box marginTop={1}>
          <DialogControls
            controls={[
              { key: "Enter", label: "Select", variant: "primary" },
              { key: "↑/↓", label: "Browse" },
            ]}
          />
        </box>
      </box>
    </Dialog>
  );
}
