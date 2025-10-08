import { useEffect, useMemo, useState } from "react";
import AlertDialog from "./alert-dialog";
import { useCommand } from "../command-provider";
import Input from "./input";
import { config } from "../../core/config";
import type { Config } from "../../core/config/config";

export default function ConfigDialog({
  configOpen,
  closeConfig,
}: {
  configOpen: boolean;
  closeConfig: () => void;
}) {
  const { commands } = useCommand();
  const [appConfig, setAppConfig] = useState<Config | null>(null);

  useEffect(() => {
    async function getConfig() {
      const _appConfig = await config.get();
      setAppConfig(_appConfig);
    }
    getConfig();
  }, []);

  return (
    <AlertDialog title="Config" open={configOpen} onClose={closeConfig}>
      <ConfigForm appConfig={appConfig} />
    </AlertDialog>
  );
}

function ConfigForm({ appConfig }: { appConfig: Config | null }) {
  if (!appConfig) {
    return <text>Loading...</text>;
  }
  return (
    <box flexDirection="column">
      <text>
        {appConfig.openAiAPIKey ? "✓" : "✗"} OpenAI:{" "}
        {appConfig.openAiAPIKey ? "Configured" : "Not set"}
      </text>
      <text>
        {appConfig.anthropicAPIKey ? "✓" : "✗"} Anthropic:{" "}
        {appConfig.anthropicAPIKey ? "Configured" : "Not set"}
      </text>
      <text>
        {appConfig.openRouterAPIKey ? "✓" : "✗"} OpenRouter:{" "}
        {appConfig.openRouterAPIKey ? "Configured" : "Not set"}
      </text>
      <text>
        {appConfig.bedrockAPIKey ? "✓" : "✗"} Bedrock:{" "}
        {appConfig.bedrockAPIKey ? "Configured" : "Not set"}
      </text>
    </box>
  );
}
