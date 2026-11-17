import type { ScrollBoxRenderable } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import { useEffect, useRef, useState } from "react";
import type { CredentialReference } from "../../../core/credentials";
import { parseHeaderLine } from "../../../core/http/parse";
import type { AuthCredentials } from "../../../core/session";
import { Dialog, useDialog } from "../../context/dialog";
import { useDimensions } from "../../context/dimensions";
import { useTheme } from "../../theme";
import DialogLayout from "../dialog-layout";

const fields = [
  ["role", "Account / role"],
  ["loginUrl", "Login URL"],
  ["username", "Username"],
  ["password", "Password"],
  ["apiKey", "API key"],
  ["bearerToken", "Bearer token"],
  ["header", "HTTP header (opt.)"],
  ["context", "Login instructions"],
] as const;

export function SessionCredentialsDialog({
  saved,
  onSave,
}: {
  saved: CredentialReference[];
  onSave: (credential: AuthCredentials) => Promise<void>;
}) {
  const { colors } = useTheme();
  const { height } = useDimensions();
  const { clear } = useDialog();
  const scroll = useRef<ScrollBoxRenderable>(null);
  const [adding, setAdding] = useState(saved.length === 0);
  const [focus, setFocus] = useState(0);
  const [draft, setDraft] = useState<
    Partial<Record<(typeof fields)[number][0], string>>
  >({});
  const [error, setError] = useState("");
  const saving = useRef(false);

  useEffect(() => {
    if (adding)
      scroll.current?.scrollChildIntoView(`credential-field-${focus}`);
  }, [adding, focus]);

  const save = async () => {
    if (saving.current) return;
    const { role, loginUrl, username, password, apiKey, bearerToken, context } =
      draft;
    if (
      !(
        username?.trim() ||
        password ||
        apiKey ||
        bearerToken ||
        context?.trim()
      )
    ) {
      setError("Enter a credential or login instructions to save.");
      return;
    }
    let customHeaders: Record<string, string> | undefined;
    const header = draft.header?.trim();
    if (header) {
      if ((!apiKey && !bearerToken) || (apiKey && bearerToken)) {
        setError(
          "To send an HTTP header, enter either an API key or a bearer token.",
        );
        return;
      }
      const parsed = parseHeaderLine(
        `${header}: ${apiKey || `Bearer ${bearerToken}`}`,
      );
      if (!parsed.ok || parsed.value.name !== header) {
        setError("Enter a valid HTTP header name and single-line secret.");
        return;
      }
      customHeaders = { [header]: parsed.value.value };
    }
    saving.current = true;
    try {
      await onSave({
        role: role?.trim() || undefined,
        loginUrl: loginUrl?.trim() || undefined,
        username: username?.trim() || undefined,
        password: password || undefined,
        apiKey: apiKey || undefined,
        tokens:
          bearerToken || customHeaders
            ? { bearerToken, customHeaders }
            : undefined,
        context: context?.trim() || undefined,
      });
      clear();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Could not save the credential.",
      );
    } finally {
      saving.current = false;
    }
  };

  useKeyboard((key) => {
    if (saving.current) {
      key.preventDefault();
      return;
    }
    if (key.name === "escape") {
      key.preventDefault();
      clear();
      return;
    }
    if (!adding && key.name === "return") {
      key.preventDefault();
      setAdding(true);
    } else if (adding && key.name === "tab") {
      key.preventDefault();
      setFocus(
        (i) => (i + (key.shift ? -1 : 1) + fields.length) % fields.length,
      );
    } else if (adding && key.name === "return") {
      key.preventDefault();
      void save();
    }
  });

  return (
    <Dialog
      size="large"
      onClose={() => {
        if (!saving.current) clear();
      }}
    >
      <DialogLayout
        title={adding ? "Add session credential" : "Session credentials"}
        footerActions={
          adding
            ? [
                { key: "Enter", label: "Save", variant: "primary" },
                { key: "Tab", label: "Next field" },
              ]
            : [{ key: "Enter", label: "Add credential", variant: "primary" }]
        }
      >
        <scrollbox
          ref={scroll}
          focused={!adding}
          height={Math.min(
            adding ? fields.length : saved.length * 3,
            Math.max(2, height - 14),
          )}
          scrollbarOptions={{
            trackOptions: {
              foregroundColor: colors.textMuted,
              backgroundColor: colors.backgroundElement,
            },
          }}
        >
          {adding
            ? fields.map(([field, label], index) => {
                const secret =
                  field === "password" ||
                  field === "apiKey" ||
                  field === "bearerToken";
                const value = draft[field] ?? "";
                return (
                  <box
                    key={field}
                    id={`credential-field-${index}`}
                    flexDirection="row"
                    height={1}
                    flexShrink={0}
                    overflow="hidden"
                    onMouseDown={() => setFocus(index)}
                  >
                    <text
                      width={22}
                      fg={index === focus ? colors.primary : colors.textMuted}
                    >
                      {index === focus ? "› " : "  "}
                      {label}
                    </text>
                    <input
                      value={value}
                      width={secret ? 0 : undefined}
                      flexGrow={secret ? 0 : 1}
                      backgroundColor="transparent"
                      textColor={colors.text}
                      focusedTextColor={colors.text}
                      focused={index === focus}
                      placeholder="—"
                      onInput={(v) => {
                        setError("");
                        setDraft((d) => ({ ...d, [field]: v }));
                      }}
                    />
                    {secret && (
                      <text fg={colors.textMuted}>
                        {value ? "••••••••" : "—"}
                      </text>
                    )}
                  </box>
                );
              })
            : saved.map((ref) => (
                <box
                  key={ref.id}
                  flexDirection="column"
                  marginBottom={1}
                  overflow="hidden"
                >
                  <text fg={colors.text}>
                    {ref.role ?? ref.username ?? ref.label ?? ref.type}
                  </text>
                  <text fg={colors.textMuted}>
                    {[ref.type, ref.loginUrl, ref.context]
                      .filter(Boolean)
                      .join(" · ")}
                  </text>
                </box>
              ))}
        </scrollbox>
        {adding && (
          <box
            flexDirection="column"
            marginTop={1}
            flexShrink={0}
            overflow="hidden"
          >
            <text fg={colors.textMuted}>
              Saved in plaintext in this session’s session.json.
            </text>
            <text fg={colors.textMuted}>
              {fields[focus][0] === "header"
                ? "An HTTP header sends this key or token on in-scope requests."
                : "Login instructions are visible to the agent."}
            </text>
          </box>
        )}
        {error && <text fg={colors.error}>{error}</text>}
      </DialogLayout>
    </Dialog>
  );
}
