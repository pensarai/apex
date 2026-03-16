import type { RGBA } from "@opentui/core";

interface DataPoint {
  label: string;
  value: number;
}

interface LineGraphProps {
  data: DataPoint[];
  width: number;
  height: number;
  color: RGBA;
  axisColor: RGBA;
  labelColor: RGBA;
  title?: string;
  titleColor?: RGBA;
  valueFormatter?: (value: number) => string;
  emptyMessage?: string;
}

const BLOCK_CHARS = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

function formatDefault(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return value.toFixed(0);
}

function renderGraphLine(
  values: number[],
  minVal: number,
  maxVal: number,
  graphWidth: number,
): string {
  if (values.length === 0) return "";

  const range = maxVal - minVal || 1;

  const interpolated: number[] = [];
  for (let i = 0; i < graphWidth; i++) {
    const t =
      values.length <= 1 ? 0 : (i / (graphWidth - 1)) * (values.length - 1);
    const lo = Math.floor(t);
    const hi = Math.min(lo + 1, values.length - 1);
    const frac = t - lo;
    interpolated.push(values[lo] + (values[hi] - values[lo]) * frac);
  }

  return interpolated
    .map((v) => {
      const normalized = (v - minVal) / range;
      const idx = Math.round(normalized * (BLOCK_CHARS.length - 1));
      return BLOCK_CHARS[Math.max(0, Math.min(idx, BLOCK_CHARS.length - 1))];
    })
    .join("");
}

export default function LineGraph({
  data,
  width,
  height: _height,
  color,
  axisColor,
  labelColor,
  title,
  titleColor,
  valueFormatter = formatDefault,
  emptyMessage = "No data available",
}: LineGraphProps) {
  if (data.length === 0) {
    return (
      <box flexDirection="column" width={width}>
        {title && <text fg={titleColor ?? color}>{title}</text>}
        <box marginTop={1}>
          <text fg={labelColor}>{emptyMessage}</text>
        </box>
      </box>
    );
  }

  const values = data.map((d) => d.value);
  const maxVal = Math.max(...values);
  const minVal = Math.min(...values, 0);

  const labelWidth = 8;
  const graphWidth = Math.max(width - labelWidth - 3, 10);

  const graphLine = renderGraphLine(values, minVal, maxVal, graphWidth);

  const startLabel = data.length > 0 ? data[0].label : "";
  const endLabel = data.length > 1 ? data[data.length - 1].label : "";
  const midIdx = Math.floor(data.length / 2);
  const midLabel = data.length > 2 ? data[midIdx].label : "";

  const xAxisPad = graphWidth - startLabel.length - endLabel.length;
  const xAxisLine =
    data.length > 2 && xAxisPad > midLabel.length + 2
      ? buildXAxisWithMid(startLabel, midLabel, endLabel, graphWidth)
      : startLabel + " ".repeat(Math.max(0, xAxisPad)) + endLabel;

  return (
    <box flexDirection="column" width={width}>
      {title && (
        <box marginBottom={1}>
          <text fg={titleColor ?? color}>{title}</text>
        </box>
      )}

      {/* Max value label + graph */}
      <box>
        <box width={labelWidth} justifyContent="flex-end">
          <text fg={labelColor}>
            {padStart(valueFormatter(maxVal), labelWidth)}
          </text>
        </box>
        <text fg={axisColor}> ┤</text>
        <text fg={color}>{graphLine}</text>
      </box>

      {/* Min value label + axis */}
      <box>
        <box width={labelWidth} justifyContent="flex-end">
          <text fg={labelColor}>
            {padStart(valueFormatter(minVal), labelWidth)}
          </text>
        </box>
        <text fg={axisColor}> └{"─".repeat(graphWidth)}</text>
      </box>

      {/* X-axis labels */}
      <box>
        <box width={labelWidth + 2} />
        <text fg={labelColor}>{xAxisLine}</text>
      </box>

      {/* Summary line */}
      <box marginTop={1}>
        <text fg={labelColor}>
          Peak: {valueFormatter(maxVal)} · Latest:{" "}
          {valueFormatter(values[values.length - 1])} · Avg:{" "}
          {valueFormatter(values.reduce((a, b) => a + b, 0) / values.length)}
        </text>
      </box>
    </box>
  );
}

function padStart(str: string, len: number): string {
  return str.length >= len ? str : " ".repeat(len - str.length) + str;
}

function buildXAxisWithMid(
  start: string,
  mid: string,
  end: string,
  totalWidth: number,
): string {
  const midPos = Math.floor(totalWidth / 2) - Math.floor(mid.length / 2);
  const afterMid = midPos + mid.length;
  const endPos = totalWidth - end.length;

  if (midPos <= start.length + 1 || afterMid >= endPos - 1) {
    return (
      start +
      " ".repeat(Math.max(0, totalWidth - start.length - end.length)) +
      end
    );
  }

  return (
    start +
    " ".repeat(midPos - start.length) +
    mid +
    " ".repeat(endPos - afterMid) +
    end
  );
}
