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

type FlowState = "choosing" | "selecting" | "inputting" | "auth";

export default function ProviderManager() {
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

    route.navigate({
      type: "base",
      path: "models",
    });
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
    route.navigate({
      type: "base",
      path: "home",
    });
  };

  const handleAuthClose = () => {
    route.navigate({ type: "base", path: "home" });
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
      {flowState === "auth" && <AuthFlow onClose={handleAuthClose} />}
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
    <box
      position="absolute"
      top={0}
      left={0}
      zIndex={1000}
      width="100%"
      height="100%"
      justifyContent="center"
      alignItems="center"
      backgroundColor={"transparent"}
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
        <box flexDirection="row" marginBottom={2}>
          <text fg={colors.primary}>Get Started</text>
        </box>

        <box marginBottom={2}>
          <text fg={colors.textMuted}>
            Choose how to connect an AI provider.
          </text>
        </box>

        {/* Choices */}
        <box flexDirection="column" gap={1}>
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
        <box marginTop={2}>
          <text fg={colors.textMuted}>
            <span fg={colors.primary}>[↑↓]</span> Navigate ·{" "}
            <span fg={colors.primary}>[ENTER]</span> Select
          </text>
        </box>
      </box>
    </box>
  );
}
