import { useState } from "react";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { config } from "../../../core/config";
import { type ProviderType, AVAILABLE_PROVIDERS } from "../../../core/providers";
import ProviderSelection from "./provider-selection";
import APIKeyInput from "./api-key-input";

type FlowState = "selecting" | "inputting";

export default function ProviderManager() {
  const route = useRoute();
  const _config = useConfig();
  const [flowState, setFlowState] = useState<FlowState>("selecting");
  const [selectedProvider, setSelectedProvider] = useState<ProviderType | null>(
    null
  );

  const handleProviderSelected = (providerId: ProviderType) => {
    setSelectedProvider(providerId);
    setFlowState("inputting");
  };

  const handleAPIKeySubmit = async (apiKey: string) => {
    if (!selectedProvider) return;

    // Update config based on provider
    const configUpdate: Record<string, string> = {};
    switch (selectedProvider) {
      case "anthropic":
        configUpdate.anthropicAPIKey = apiKey;
        break;
      case "openai":
        configUpdate.openAiAPIKey = apiKey;
        break;
      case "openrouter":
        configUpdate.openRouterAPIKey = apiKey;
        break;
      case "bedrock":
        configUpdate.bedrockAPIKey = apiKey;
        break;
    }

    // Save to config
    await config.update(configUpdate);

    // Reload config in context
    await _config.reload();

    // Navigate to models to select a model
    route.navigate({
      type: "base",
      path: "models",
    });
  };

  const handleAPIKeyCancel = () => {
    setFlowState("selecting");
    setSelectedProvider(null);
  };

  const handleClose = () => {
    route.navigate({
      type: "base",
      path: "home",
    });
  };

  const selectedProviderInfo = AVAILABLE_PROVIDERS.find(
    (p) => p.id === selectedProvider
  );

  return (
    <>
      {flowState === "selecting" && (
        <ProviderSelection
          onProviderSelected={handleProviderSelected}
          onClose={handleClose}
        />
      )}
      {flowState === "inputting" && selectedProvider && selectedProviderInfo && (
        <APIKeyInput
          provider={selectedProvider}
          providerName={selectedProviderInfo.name}
          onSubmit={handleAPIKeySubmit}
          onCancel={handleAPIKeyCancel}
        />
      )}
    </>
  );
}
