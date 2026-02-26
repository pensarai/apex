import Input from "../../input";
import { useTheme } from "../../../theme";

interface ScopeState {
  allowedHosts: string[];
  allowedPorts?: string[];
  strictScope: boolean;
  enumerateSubdomains?: boolean;
}

interface ScopeSectionProps {
  expanded: boolean;
  focusedField: number;
  scope: ScopeState;
  onUpdate: (scope: ScopeState) => void;
  /** Input state for the host field (managed by parent for Enter-to-add) */
  hostInput: string;
  onHostInputChange: (value: string) => void;
  /** Input state for the port field. Omit to hide port input. */
  portInput?: string;
  onPortInputChange?: (value: string) => void;
  /** Whether to show the subdomain enumeration toggle */
  showSubdomainToggle?: boolean;
}

export function ScopeSection({
  expanded,
  focusedField,
  scope,
  onUpdate,
  hostInput,
  onHostInputChange,
  portInput,
  onPortInputChange,
  showSubdomainToggle = false,
}: ScopeSectionProps) {
  const { colors } = useTheme();

  const hasPorts = portInput !== undefined && onPortInputChange !== undefined;

  // Field mapping:
  // 0 = host input
  // 1 = port input (if shown)
  // next = strict scope toggle
  // next+1 = subdomain toggle (if shown)
  const strictScopeFieldIndex = hasPorts ? 2 : 1;
  const subdomainFieldIndex = strictScopeFieldIndex + 1;

  return (
    <box flexDirection="column" gap={1}>
      <text>
        <span fg={colors.primary}>█ </span>
        <span fg={expanded ? colors.text : colors.textMuted}>
          Scope Constraints
        </span>
      </text>
      {expanded && (
        <box flexDirection="column" gap={1} paddingLeft={2}>
          <Input
            label="Add Allowed Host"
            description="Press Enter to add"
            placeholder="example.com"
            value={hostInput}
            onInput={onHostInputChange}
            focused={focusedField === 0}
          />
          {scope.allowedHosts.length > 0 && (
            <box flexDirection="column" paddingLeft={2}>
              {scope.allowedHosts.map((h, i) => (
                <text key={i} fg={colors.textMuted}>
                  • {h}
                </text>
              ))}
            </box>
          )}

          {hasPorts && (
            <>
              <Input
                label="Add Allowed Port"
                description="Press Enter to add"
                placeholder="443"
                value={portInput!}
                onInput={onPortInputChange!}
                focused={focusedField === 1}
              />
              {(scope.allowedPorts?.length ?? 0) > 0 && (
                <box flexDirection="column" paddingLeft={2}>
                  {scope.allowedPorts!.map((p, i) => (
                    <text key={i} fg={colors.textMuted}>
                      • {p}
                    </text>
                  ))}
                </box>
              )}
            </>
          )}

          <box flexDirection="row" gap={1}>
            <text
              fg={
                focusedField === strictScopeFieldIndex
                  ? colors.text
                  : colors.textMuted
              }
            >
              Strict Scope:
            </text>
            <text fg={scope.strictScope ? colors.primary : colors.textMuted}>
              {scope.strictScope ? "● Enabled" : "○ Disabled"}
            </text>
            {focusedField === strictScopeFieldIndex && (
              <text fg={colors.textMuted}>(↑/↓ to toggle)</text>
            )}
          </box>

          {showSubdomainToggle && (
            <box flexDirection="row" gap={1}>
              <text
                fg={
                  focusedField === subdomainFieldIndex
                    ? colors.primary
                    : colors.textMuted
                }
              >
                Enumerate Subdomains:
              </text>
              <text
                fg={
                  scope.enumerateSubdomains ? colors.primary : colors.textMuted
                }
              >
                {scope.enumerateSubdomains ? "● Enabled" : "○ Disabled"}
              </text>
              {focusedField === subdomainFieldIndex && (
                <text fg={colors.textMuted}>(↑/↓ to toggle)</text>
              )}
            </box>
          )}
        </box>
      )}
    </box>
  );
}
