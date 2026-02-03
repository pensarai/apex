import { useEffect, useMemo, useState } from "react";
import AlertDialog from "../alert-dialog";
import { config } from "../../../core/config";
import type { Config } from "../../../core/config/config";
import { useRoute } from "../../context/route";

export default function ConfigDialog() {
  const route = useRoute();
  
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if(route.data.type === "base" && route.data.path === "config") {
      setOpen(true);
    } else {
      setOpen(false);
    }
  }, [route]);

  const closeAlert = () => {
    setOpen(false);
    route.navigate({
      type: "base",
      path: "home"
    });
  }

  const [appConfig, setAppConfig] = useState<Config | null>(null);

  useEffect(() => {
    async function getConfig() {
      const _appConfig = await config.get();
      setAppConfig(_appConfig);
    }
    getConfig();
  }, []);

  return (
    <AlertDialog title="Config" open={open} onClose={closeAlert}>
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