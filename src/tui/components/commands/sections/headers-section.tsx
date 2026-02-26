import Input from "../../input";
import { useTheme } from "../../../theme";

type HeadersMode = "none" | "default" | "custom";

interface HeadersState {
  mode: HeadersMode;
  customHeaders: Record<string, string>;
}

interface HeadersSectionProps {
  expanded: boolean;
  focusedField: number;
  headers: HeadersState;
  onUpdate: (headers: HeadersState) => void;
  /** Input state for header name (managed by parent for Enter-to-add) */
  headerNameInput: string;
  onHeaderNameInputChange: (value: string) => void;
  /** Input state for header value */
  headerValueInput: string;
  onHeaderValueInputChange: (value: string) => void;
}

export function HeadersSection({
  expanded,
  focusedField,
  headers,
  onUpdate,
  headerNameInput,
  onHeaderNameInputChange,
  headerValueInput,
  onHeaderValueInputChange,
}: HeadersSectionProps) {
  const { colors } = useTheme();

  return (
    <box flexDirection="column" gap={1}>
      <text>
        <span fg={colors.primary}>█ </span>
        <span fg={expanded ? colors.text : colors.textMuted}>
          Request Headers
        </span>
      </text>
      {expanded && (
        <box flexDirection="column" gap={1} paddingLeft={2}>
          <box flexDirection="column">
            <text
              fg={headers.mode === "none" ? colors.primary : colors.textMuted}
            >
              {headers.mode === "none" ? "●" : "○"} None
            </text>
            <text
              fg={
                headers.mode === "default" ? colors.primary : colors.textMuted
              }
            >
              {headers.mode === "default" ? "●" : "○"} Default (User-Agent:
              pensar-apex)
            </text>
            <text
              fg={headers.mode === "custom" ? colors.primary : colors.textMuted}
            >
              {headers.mode === "custom" ? "●" : "○"} Custom
            </text>
          </box>
          {focusedField === 0 && (
            <text fg={colors.textMuted}>Use ↑/↓ to select</text>
          )}

          {headers.mode === "custom" && (
            <box flexDirection="column" gap={1}>
              <Input
                label="Header Name"
                placeholder="X-Custom-Header"
                value={headerNameInput}
                onInput={onHeaderNameInputChange}
                focused={focusedField === 1}
              />
              <Input
                label="Header Value"
                placeholder="value"
                value={headerValueInput}
                onInput={onHeaderValueInputChange}
                focused={focusedField === 2}
              />
              {Object.keys(headers.customHeaders).length > 0 && (
                <box flexDirection="column">
                  {Object.entries(headers.customHeaders).map(([k, v]) => (
                    <text key={k} fg={colors.textMuted}>
                      • {k}: {v}
                    </text>
                  ))}
                </box>
              )}
            </box>
          )}
        </box>
      )}
    </box>
  );
}
