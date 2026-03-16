import { useState, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { useTheme } from "../../theme";
import {
  fetchCiUsage,
  type CiUsageResponse,
  type UsagePeriod,
} from "../../../core/api/ci-usage";
import LineGraph from "./line-graph";

type CiUsageStep = "loading" | "no-auth" | "display" | "error";

const PERIODS: { key: UsagePeriod; label: string; shortLabel: string }[] = [
  { key: "week", label: "1 Week", shortLabel: "1W" },
  { key: "month", label: "1 Month", shortLabel: "1M" },
  { key: "year", label: "1 Year", shortLabel: "1Y" },
];

interface CiUsageProps {
  onOpenAuthDialog?: () => void;
}

export default function CiUsage({ onOpenAuthDialog }: CiUsageProps) {
  const route = useRoute();
  const appConfig = useConfig();
  const { colors } = useTheme();

  const [step, setStep] = useState<CiUsageStep>("loading");
  const [usageData, setUsageData] = useState<CiUsageResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [periodIndex, setPeriodIndex] = useState(0);
  const [selectedModelIndex, setSelectedModelIndex] = useState(0);
  const [graphsEnabled, setGraphsEnabled] = useState(true);
  const [modelFilterEnabled, setModelFilterEnabled] = useState(true);

  const currentPeriod = PERIODS[periodIndex];
  const models = usageData?.models ?? [];
  const allModelsOption = "All Models";
  const modelOptions = [allModelsOption, ...models];
  const selectedModelDisplay =
    modelOptions[selectedModelIndex] ?? allModelsOption;
  const selectedModelParam =
    selectedModelIndex === 0 ? null : models[selectedModelIndex - 1];

  const goHome = () => {
    route.navigate({ type: "base", path: "home" });
  };

  const fetchData = async (period?: UsagePeriod, model?: string | null) => {
    setStep("loading");
    setErrorMsg(null);

    const result = await fetchCiUsage(
      appConfig.data,
      period ?? currentPeriod.key,
      model !== undefined ? model : selectedModelParam,
    );

    if (result === null) {
      const hasAuth = appConfig.data.accessToken || appConfig.data.pensarAPIKey;
      if (!hasAuth) {
        setStep("no-auth");
      } else {
        setErrorMsg("Failed to fetch usage data. Check your connection.");
        setStep("error");
      }
      return;
    }

    setUsageData(result);
    setStep("display");
  };

  useEffect(() => {
    fetchData();
  }, []);

  useKeyboard((key) => {
    if (key.name === "escape") {
      goHome();
      return;
    }

    if (step === "no-auth" && key.name === "return") {
      onOpenAuthDialog?.();
      return;
    }

    if (step === "error" && (key.raw === "r" || key.raw === "R")) {
      fetchData();
      return;
    }

    if (step !== "display") return;

    if (key.raw === "r" || key.raw === "R") {
      fetchData();
      return;
    }

    if (key.name === "left" || key.raw === "h" || key.raw === "H") {
      const newIndex = (periodIndex - 1 + PERIODS.length) % PERIODS.length;
      setPeriodIndex(newIndex);
      fetchData(PERIODS[newIndex].key);
      return;
    }

    if (key.name === "right" || key.raw === "l" || key.raw === "L") {
      const newIndex = (periodIndex + 1) % PERIODS.length;
      setPeriodIndex(newIndex);
      fetchData(PERIODS[newIndex].key);
      return;
    }

    if (key.raw === "g" || key.raw === "G") {
      setGraphsEnabled((prev) => !prev);
      return;
    }

    if (key.raw === "m" || key.raw === "M") {
      setModelFilterEnabled((prev) => !prev);
      return;
    }

    if (
      modelFilterEnabled &&
      (key.name === "up" || key.raw === "k" || key.raw === "K")
    ) {
      setSelectedModelIndex((prev) => {
        const newIdx = (prev - 1 + modelOptions.length) % modelOptions.length;
        const newModel = newIdx === 0 ? null : models[newIdx - 1];
        fetchData(currentPeriod.key, newModel);
        return newIdx;
      });
      return;
    }

    if (
      modelFilterEnabled &&
      (key.name === "down" || key.raw === "j" || key.raw === "J")
    ) {
      setSelectedModelIndex((prev) => {
        const newIdx = (prev + 1) % modelOptions.length;
        const newModel = newIdx === 0 ? null : models[newIdx - 1];
        fetchData(currentPeriod.key, newModel);
        return newIdx;
      });
      return;
    }
  });

  const graphData = (usageData?.data ?? []).map((d) => ({
    label: formatDateLabel(d.date, currentPeriod.key),
    value: d.totalTokens,
  }));

  const costData = (usageData?.data ?? []).map((d) => ({
    label: formatDateLabel(d.date, currentPeriod.key),
    value: d.cost,
  }));

  const requestData = (usageData?.data ?? []).map((d) => ({
    label: formatDateLabel(d.date, currentPeriod.key),
    value: d.requests,
  }));

  return (
    <box
      flexDirection="column"
      width="100%"
      maxWidth={90}
      alignItems="flex-start"
      paddingLeft={2}
      paddingTop={1}
    >
      {/* Header */}
      <box marginBottom={1}>
        <text fg={colors.primary}>█ </text>
        <text fg={colors.text}>CI Usage</text>
        <text fg={colors.textMuted}> — Historical Analytics</text>
      </box>

      {/* Period selector */}
      <box marginBottom={1}>
        <text fg={colors.textMuted}>Period: </text>
        {PERIODS.map((p, i) => (
          <text
            key={p.key}
            fg={i === periodIndex ? colors.primary : colors.textMuted}
          >
            {i === periodIndex ? `[${p.shortLabel}]` : ` ${p.shortLabel} `}
            {i < PERIODS.length - 1 ? " · " : ""}
          </text>
        ))}
        <text fg={colors.textMuted}>{"  "}(←/→ to switch)</text>
      </box>

      {/* Model filter (hidden when disabled) */}
      {modelFilterEnabled && (
        <box marginBottom={1}>
          <text fg={colors.textMuted}>Model: </text>
          <text fg={colors.secondary}>{selectedModelDisplay}</text>
          {models.length > 0 && (
            <text fg={colors.textMuted}>{"  "}(↑/↓ to cycle)</text>
          )}
        </box>
      )}

      {/* Loading state */}
      {step === "loading" && (
        <box marginTop={1}>
          <text fg={colors.warning}>Fetching usage data...</text>
        </box>
      )}

      {/* No auth state */}
      {step === "no-auth" && (
        <box flexDirection="column" gap={1}>
          <text fg={colors.warning}>Not connected to Pensar Console.</text>
          <text fg={colors.textMuted}>
            Run <span fg={colors.success}>/auth</span> first to connect your
            account.
          </text>
          <box marginTop={1}>
            <text fg={colors.textMuted}>
              <span fg={colors.success}>[ENTER]</span> Run /auth ·{" "}
              <span fg={colors.success}>[ESC]</span> Back
            </text>
          </box>
        </box>
      )}

      {/* Error state */}
      {step === "error" && (
        <box flexDirection="column" gap={1}>
          <text fg={colors.error}>Error: {errorMsg}</text>
          <box marginTop={1}>
            <text fg={colors.textMuted}>
              <span fg={colors.success}>[R]</span> Retry ·{" "}
              <span fg={colors.success}>[ESC]</span> Back
            </text>
          </box>
        </box>
      )}

      {/* Display state */}
      {step === "display" && usageData && (
        <box flexDirection="column" width="100%">
          {/* Summary */}
          <box flexDirection="column" marginBottom={1}>
            <box>
              <text fg={colors.primary}>█ </text>
              <text fg={colors.text}>Summary</text>
              <text fg={colors.textMuted}> ({currentPeriod.label})</text>
            </box>
            <box paddingLeft={2} marginTop={1} flexDirection="column">
              <text fg={colors.text}>
                Requests:{" "}
                <span fg={colors.secondary}>
                  {usageData.summary.totalRequests.toLocaleString()}
                </span>
                {"  "}Tokens:{" "}
                <span fg={colors.secondary}>
                  {formatTokens(usageData.summary.totalTokens)}
                </span>
                {"  "}Cost:{" "}
                <span fg={colors.success}>
                  ${usageData.summary.totalCost.toFixed(2)}
                </span>
              </text>
              <text fg={colors.textMuted}>
                Avg/day: {usageData.summary.averageDailyRequests.toFixed(0)} req
                · ${usageData.summary.averageDailyCost.toFixed(2)}
              </text>
            </box>
          </box>

          {/* Graphs (hidden when disabled) */}
          {graphsEnabled && (
            <box flexDirection="column" marginTop={1} width="100%">
              <LineGraph
                data={graphData}
                width={72}
                height={8}
                color={colors.primary}
                axisColor={colors.borderSubtle}
                labelColor={colors.textMuted}
                title="Token Usage"
                titleColor={colors.text}
                valueFormatter={formatTokens}
                emptyMessage="No token data for this period"
              />

              <box marginTop={1}>
                <LineGraph
                  data={costData}
                  width={72}
                  height={8}
                  color={colors.success}
                  axisColor={colors.borderSubtle}
                  labelColor={colors.textMuted}
                  title="Cost ($)"
                  titleColor={colors.text}
                  valueFormatter={(v) => `$${v.toFixed(2)}`}
                  emptyMessage="No cost data for this period"
                />
              </box>

              <box marginTop={1}>
                <LineGraph
                  data={requestData}
                  width={72}
                  height={8}
                  color={colors.secondary}
                  axisColor={colors.borderSubtle}
                  labelColor={colors.textMuted}
                  title="Requests"
                  titleColor={colors.text}
                  emptyMessage="No request data for this period"
                />
              </box>
            </box>
          )}

          {/* Footer / Controls */}
          <box flexDirection="column" marginTop={2}>
            <text fg={colors.primary}>█ </text>
            <box flexDirection="column" paddingLeft={2}>
              <text fg={colors.textMuted}>
                <span fg={colors.text}>[←/→]</span> Period{"  "}
                {modelFilterEnabled && models.length > 0 && (
                  <>
                    <span fg={colors.text}>[↑/↓]</span> Model{"  "}
                  </>
                )}
                <span fg={colors.text}>[R]</span> Refresh{"  "}
                <span fg={colors.text}>[ESC]</span> Back
              </text>
              <text fg={colors.textMuted}>
                <span fg={colors.text}>[G]</span> Toggle graphs
                <span fg={graphsEnabled ? colors.success : colors.textMuted}>
                  {graphsEnabled ? " ✓" : " ✗"}
                </span>
                {"  "}
                <span fg={colors.text}>[M]</span> Toggle model filter
                <span
                  fg={modelFilterEnabled ? colors.success : colors.textMuted}
                >
                  {modelFilterEnabled ? " ✓" : " ✗"}
                </span>
              </text>
            </box>
          </box>
        </box>
      )}
    </box>
  );
}

function formatDateLabel(dateStr: string, period: UsagePeriod): string {
  const d = new Date(dateStr);
  if (period === "year") {
    return d.toLocaleDateString("en-US", { month: "short" });
  }
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

function formatTokens(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return value.toFixed(0);
}
