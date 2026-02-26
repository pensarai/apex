import Input from "../../input";
import { useTheme } from "../../../theme";

interface AuthState {
  loginUrl: string;
  username: string;
  password: string;
  instructions: string;
}

interface AuthSectionProps {
  /** Whether this section is the currently focused section */
  expanded: boolean;
  /** Which field within the section is focused (0-3) */
  focusedField: number;
  auth: AuthState;
  onUpdate: (auth: AuthState) => void;
}

export function AuthSection({
  expanded,
  focusedField,
  auth,
  onUpdate,
}: AuthSectionProps) {
  const { colors } = useTheme();

  const updateField = (field: keyof AuthState, value: string) => {
    onUpdate({ ...auth, [field]: value });
  };

  return (
    <box flexDirection="column" gap={1}>
      <text>
        <span fg={colors.primary}>█ </span>
        <span fg={expanded ? colors.text : colors.textMuted}>
          Authentication
        </span>
      </text>
      {expanded && (
        <box flexDirection="column" gap={1} paddingLeft={2}>
          <Input
            label="Login URL"
            placeholder="https://example.com/login"
            value={auth.loginUrl}
            onInput={(v) => updateField("loginUrl", v)}
            onPaste={(event) => {
              const cleaned = String(event.text).replace(/\r?\n/g, " ");
              updateField("loginUrl", auth.loginUrl + cleaned);
            }}
            focused={focusedField === 0}
          />
          <Input
            label="Username"
            placeholder="admin"
            value={auth.username}
            onInput={(v) => updateField("username", v)}
            onPaste={(event) => {
              const cleaned = String(event.text).replace(/\r?\n/g, " ");
              updateField("username", auth.username + cleaned);
            }}
            focused={focusedField === 1}
          />
          <Input
            label="Password"
            placeholder="••••••••"
            value={auth.password}
            onInput={(v) => updateField("password", v)}
            onPaste={(event) => {
              const cleaned = String(event.text).replace(/\r?\n/g, " ");
              updateField("password", auth.password + cleaned);
            }}
            focused={focusedField === 2}
          />
          <Input
            label="Auth Instructions"
            placeholder="Use OAuth flow, extract bearer token..."
            value={auth.instructions}
            onInput={(v) => updateField("instructions", v)}
            onPaste={(event) => {
              const cleaned = String(event.text).replace(/\r?\n/g, " ");
              updateField("instructions", auth.instructions + cleaned);
            }}
            focused={focusedField === 3}
          />
        </box>
      )}
    </box>
  );
}

/** Number of focusable fields in the auth section */
export const AUTH_FIELD_COUNT = 4;
