import { Button } from "@pensarai/design-system/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@pensarai/design-system/ui/dialog";
import { Input } from "@pensarai/design-system/ui/input";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@pensarai/design-system/ui/tabs";
import { useCallback, useEffect, useState } from "react";
import { api } from "../view/bridge";
import { AccountPanel } from "./AccountPanel";
import { themes } from "./appearance";
import type {
  Advanced,
  Appearance,
  KeyProvider,
  ServiceKey,
  SettingsChange,
  SettingsSnapshot,
  SettingsTab,
} from "./contract";

type EditorProps = {
  data: SettingsSnapshot;
  save: (change: SettingsChange) => Promise<boolean>;
};
const tabs: SettingsTab[] = [
  "Providers",
  "Models",
  "Account",
  "Advanced",
  "Appearance",
];

function Providers({
  data,
  save,
  toAccount,
}: EditorProps & { toAccount: () => void }) {
  const [id, choose] = useState(data.providers[0]?.id ?? "anthropic");
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(data.local.url);
  const [name, setName] = useState(data.local.name);
  const provider = data.providers.find((p) => p.id === id);
  return (
    <div className="settings-stack">
      <label>
        AI provider
        <select
          value={id}
          onChange={(e) => {
            choose(e.target.value as typeof id);
            setKey("");
          }}
        >
          {data.providers.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
              {p.keySource === "environment"
                ? " · environment"
                : p.keySource === "saved"
                  ? " · saved key"
                  : p.configured
                    ? " · configured"
                    : ""}
            </option>
          ))}
        </select>
      </label>
      {id === "pensar" ? (
        <Button onClick={toAccount}>Manage Console account</Button>
      ) : id === "local" ? (
        <form
          className="settings-stack"
          onSubmit={async (e) => {
            e.preventDefault();
            await save({ kind: "local", url, name });
          }}
        >
          <label>
            OpenAI-compatible endpoint
            <Input
              type="url"
              required
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="http://localhost:1234/v1"
            />
          </label>
          <label>
            Local model ID
            <Input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <div className="actions">
            <Button type="submit">Save endpoint</Button>
            {provider?.configured && (
              <Button
                type="button"
                onClick={async () => {
                  if (await save({ kind: "local", url: "", name: "" })) {
                    setUrl("");
                    setName("");
                  }
                }}
              >
                Remove endpoint
              </Button>
            )}
          </div>
        </form>
      ) : (
        <form
          className="settings-stack"
          onSubmit={async (e) => {
            e.preventDefault();
            if (await save({ kind: "provider", id: id as KeyProvider, key }))
              setKey("");
          }}
        >
          {provider?.keySource === "environment" && (
            <p className="settings-key-source">
              Using <code>{provider.environmentVariable}</code> from the
              environment. Save a key here to override it. To remove the
              environment key, unset that variable and restart Apex.
            </p>
          )}
          {provider?.keySource === "saved" && (
            <p className="settings-key-source">
              Using the saved API key. Replacements apply to the next turn.
            </p>
          )}
          <label>
            {provider?.configured ? "Replace API key" : "API key"}
            <Input
              type="password"
              required
              autoComplete="off"
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
          </label>
          <div className="actions">
            <Button type="submit">Verify and save</Button>
            {provider?.keySource === "saved" && (
              <Button
                type="button"
                onClick={async () => {
                  if (
                    await save({
                      kind: "provider",
                      id: id as KeyProvider,
                      key: null,
                    })
                  )
                    setKey("");
                }}
              >
                Remove saved key
              </Button>
            )}
          </div>
        </form>
      )}
      <CustomProvider data={data} save={save} />
      {data.catalogError && <p role="alert">{data.catalogError}</p>}
    </div>
  );
}

function CustomProvider({ data, save }: EditorProps) {
  const sample = JSON.stringify(
    {
      baseUrl: "http://localhost:8000/v1",
      models: [{ id: "model-id", contextLength: 32768, maxOutputTokens: 4096 }],
    },
    null,
    2,
  );
  const [selected, select] = useState("");
  const [id, setId] = useState("");
  const [definition, edit] = useState(sample);
  const current = data.custom.find((p) => p.id === selected);
  function choose(next: string) {
    select(next);
    setId(next);
    edit(data.custom.find((p) => p.id === next)?.definition ?? sample);
  }
  return (
    <details>
      <summary>Custom providers ({data.custom.length})</summary>
      <form
        className="settings-stack"
        onSubmit={async (e) => {
          e.preventDefault();
          if (await save({ kind: "custom", id, definition })) select(id);
        }}
      >
        <label>
          Provider
          <select value={selected} onChange={(e) => choose(e.target.value)}>
            <option value="">Add provider</option>
            {data.custom.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Provider ID
          <Input
            value={id}
            required
            readOnly={!!selected}
            pattern="[A-Za-z0-9_\-]+"
            onChange={(e) => setId(e.target.value)}
          />
        </label>
        <label>
          Provider definition (JSON)
          <textarea
            rows={8}
            required
            value={definition}
            readOnly={current?.fromEnvironment}
            onChange={(e) => edit(e.target.value)}
          />
        </label>
        {current?.fromEnvironment ? (
          <p>This provider is managed by APEX_CUSTOM_PROVIDERS.</p>
        ) : (
          <>
            <p>
              Use apiKeyEnv for a bearer credential. For the same endpoint
              origin, omitted headers and requestBody are retained. Use null to
              remove either field.
            </p>
            <div className="actions">
              <Button type="submit">Save provider</Button>
              {current && (
                <Button
                  type="button"
                  onClick={async () => {
                    if (await save({ kind: "custom", id, definition: null }))
                      choose("");
                  }}
                >
                  Remove provider
                </Button>
              )}
            </div>
          </>
        )}
      </form>
    </details>
  );
}

function Models({ data, save }: EditorProps) {
  const [search, filter] = useState("");
  const [id, setId] = useState(data.selected ?? data.models[0]?.id ?? "");
  const model = data.models.find((m) => m.id === id);
  const [reasoning, setReasoning] = useState(model?.reasoning);
  const terms = search
    .trim()
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  const members = data.models.filter((m) =>
    terms.every((term) =>
      `${m.id} ${m.name} ${m.provider}`.toLowerCase().includes(term),
    ),
  );
  const providers = [...new Set(members.map((m) => m.provider))];
  function choose(id: string) {
    setId(id);
    setReasoning(data.models.find((m) => m.id === id)?.reasoning);
  }
  return (
    <div className="settings-stack">
      <label>
        Filter models
        <Input
          type="search"
          value={search}
          onChange={(e) => filter(e.target.value)}
          placeholder="Name or provider"
        />
      </label>
      {members.length ? (
        <label>
          Available models
          <select size={7} value={id} onChange={(e) => choose(e.target.value)}>
            {data.recent.some((id) => members.some((m) => m.id === id)) && (
              <optgroup label="Recent models">
                {data.recent.flatMap((id) => {
                  const m = members.find((m) => m.id === id);
                  return m
                    ? [
                        <option key={id} value={id}>
                          {m.name}
                        </option>,
                      ]
                    : [];
                })}
              </optgroup>
            )}
            {providers.map((p) => (
              <optgroup label={p} key={p}>
                {members
                  .filter((m) => m.provider === p)
                  .map((m) => (
                    <option value={m.id} key={m.id}>
                      {m.name}
                    </option>
                  ))}
              </optgroup>
            ))}
          </select>
        </label>
      ) : (
        <p>
          {search
            ? "No matching models."
            : "Configure an AI provider to select a model."}
        </p>
      )}
      {model && members.some((m) => m.id === model.id) && (
        <>
          <p className="settings-value">{model.id}</p>
          {!!model.choices.length && (
            <label>
              Reasoning effort
              <select
                value={reasoning ?? "default"}
                onChange={(e) =>
                  setReasoning(e.target.value as typeof reasoning)
                }
              >
                {model.choices.map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
          )}
          <Button onClick={() => save({ kind: "model", id, reasoning })}>
            Save model
          </Button>
        </>
      )}
      {data.catalogError && <p role="alert">{data.catalogError}</p>}
    </div>
  );
}

function AdvancedPanel({ data, save }: EditorProps) {
  const [draft, setDraft] = useState<Advanced>(data.advanced);
  const [limit, setLimit] = useState(
    String(draft.budget.limit / (draft.budget.kind === "time" ? 1000 : 1)),
  );
  const [service, setService] = useState<ServiceKey>("daytonaAPIKey");
  const [secret, setSecret] = useState("");
  const [header, setHeader] = useState("");
  const [value, setValue] = useState("");
  return (
    <div className="settings-stack">
      <form
        className="settings-stack"
        onSubmit={async (e) => {
          e.preventDefault();
          await save({
            kind: "advanced",
            value: {
              ...draft,
              budget: {
                kind: draft.budget.kind,
                limit:
                  Number(limit) * (draft.budget.kind === "time" ? 1000 : 1),
              },
            },
          });
        }}
      >
        <label>
          Operator execution mode
          <select
            value={draft.mode}
            onChange={(e) =>
              setDraft({ ...draft, mode: e.target.value as Advanced["mode"] })
            }
          >
            <option value="standard">Standard</option>
            <option value="strike">Strike</option>
            <option value="lance">Lance</option>
          </select>
        </label>
        {draft.mode !== "standard" && (
          <label>
            Finding judge
            <select
              value={draft.findingPolicy}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  findingPolicy: e.target.value as Advanced["findingPolicy"],
                })
              }
            >
              <option value="native">Enabled (Apex judge)</option>
              <option value="external">Disabled</option>
            </select>
          </label>
        )}
        {draft.mode === "lance" && (
          <>
            <label>
              Budget
              <select
                value={draft.budget.kind}
                onChange={(e) => {
                  const kind = e.target.value as Advanced["budget"]["kind"];
                  setDraft({ ...draft, budget: { ...draft.budget, kind } });
                  setLimit(
                    kind === "time"
                      ? "900"
                      : kind === "steps"
                        ? "200"
                        : "1000000",
                  );
                }}
              >
                <option value="steps">Steps</option>
                <option value="tokens">Tokens</option>
                <option value="time">Time</option>
              </select>
            </label>
            <label>
              Limit (
              {draft.budget.kind === "time" ? "seconds" : draft.budget.kind})
              <Input
                type="number"
                required
                step={draft.budget.kind === "time" ? 0.001 : 1}
                min={draft.budget.kind === "time" ? 0.002 : 1}
                value={limit}
                onChange={(e) => setLimit(e.target.value)}
              />
            </label>
          </>
        )}
        <label className="settings-check">
          <input
            type="checkbox"
            checked={draft.surface}
            onChange={(e) => setDraft({ ...draft, surface: e.target.checked })}
          />
          Use Surface for whitebox discovery
        </label>
        <Button type="submit">Save execution settings</Button>
      </form>
      <details>
        <summary>Default HTTP headers ({data.headers.length})</summary>
        <div className="settings-stack">
          {data.headers.map((h) => (
            <div key={h.name} className="settings-row">
              <code>
                {h.name} · {h.display}
              </code>
              <Button
                size="xs"
                onClick={() =>
                  save({ kind: "header", name: h.name, value: null })
                }
              >
                Remove {h.name}
              </Button>
            </div>
          ))}
          <form
            className="settings-stack"
            onSubmit={async (e) => {
              e.preventDefault();
              if (await save({ kind: "header", name: header, value })) {
                setHeader("");
                setValue("");
              }
            }}
          >
            <label>
              Header name
              <Input
                required
                value={header}
                onChange={(e) => setHeader(e.target.value)}
              />
            </label>
            <label>
              Value
              <Input
                type="password"
                autoComplete="off"
                value={value}
                onChange={(e) => setValue(e.target.value)}
              />
            </label>
            <Button type="submit">Set header</Button>
          </form>
        </div>
      </details>
      <details>
        <summary>Sandbox and search credentials</summary>
        <form
          className="settings-stack"
          onSubmit={async (e) => {
            e.preventDefault();
            if (await save({ kind: "service", id: service, value: secret }))
              setSecret("");
          }}
        >
          <label>
            Service
            <select
              value={service}
              onChange={(e) => {
                setService(e.target.value as ServiceKey);
                setSecret("");
              }}
            >
              {Object.entries({
                daytonaAPIKey: "Daytona API key",
                daytonaOrgId: "Daytona organization",
                runloopAPIKey: "Runloop API key",
                braveAPIKey: "Brave Search API key",
                exaAPIKey: "Exa API key",
              }).map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                  {data.services[id as ServiceKey] ? " · configured" : ""}
                </option>
              ))}
            </select>
          </label>
          <label>
            Value
            <Input
              type="password"
              autoComplete="off"
              required
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
          </label>
          <div className="actions">
            <Button type="submit">Save value</Button>
            {data.services[service] && (
              <Button
                type="button"
                onClick={() =>
                  save({ kind: "service", id: service, value: null })
                }
              >
                Remove saved value
              </Button>
            )}
          </div>
        </form>
      </details>
    </div>
  );
}
function AppearancePanel({ data, save }: EditorProps) {
  const [value, change] = useState<Appearance>(data.appearance);
  return (
    <form
      className="settings-stack"
      onSubmit={async (e) => {
        e.preventDefault();
        await save({ kind: "appearance", value });
      }}
    >
      <label>
        Theme
        <select
          value={value.theme}
          onChange={(e) => change({ ...value, theme: e.target.value })}
        >
          {Object.entries(themes).map(([id, t]) => (
            <option key={id} value={id}>
              {t.name}
            </option>
          ))}
        </select>
      </label>
      <label>
        Color mode
        <select
          value={value.mode}
          onChange={(e) =>
            change({ ...value, mode: e.target.value as Appearance["mode"] })
          }
        >
          <option value="auto">Follow system</option>
          <option value="dark">Dark</option>
          <option value="light">Light</option>
        </select>
      </label>
      <label className="settings-check">
        <input
          type="checkbox"
          checked={value.transparent}
          onChange={(e) => change({ ...value, transparent: e.target.checked })}
        />
        Use a transparent workspace background
      </label>
      <label className="settings-check">
        <input
          type="checkbox"
          checked={value.obfuscate}
          onChange={(e) => change({ ...value, obfuscate: e.target.checked })}
        />
        Obfuscate sensitive text in this app session
      </label>
      <Button type="submit">Save appearance</Button>
    </form>
  );
}

export default function Settings({
  onClose,
  initialTab = "Providers",
}: {
  onClose: () => void;
  initialTab?: SettingsTab;
}) {
  const [tab, select] = useState<SettingsTab>(initialTab);
  const [data, setData] = useState<SettingsSnapshot>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const refresh = useCallback(() => {
    void api
      .desktopSettings()
      .then(setData)
      .catch((e) => setError(String(e)));
  }, []);
  useEffect(() => {
    refresh();
  }, [refresh]);
  const save = async (change: SettingsChange) => {
    setBusy(true);
    setSaved(false);
    setError("");
    try {
      const next = await api.changeSettings(change);
      setData(next);
      setSaved(true);
      window.dispatchEvent(new CustomEvent("apex:settings", { detail: next }));
      if (change.kind === "appearance")
        window.dispatchEvent(
          new CustomEvent("apex:appearance", { detail: next.appearance }),
        );
      return true;
    } catch (e) {
      setError(String(e));
      return false;
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="apex-settings">
        <DialogHeader>
          <DialogTitle>Settings</DialogTitle>
          <DialogDescription>
            Apex configuration for this machine.
          </DialogDescription>
        </DialogHeader>
        <Tabs
          value={tab}
          onValueChange={(value) => {
            select(value as SettingsTab);
            setSaved(false);
            setError("");
          }}
        >
          <TabsList variant="line" aria-label="Settings sections">
            {tabs.map((t) => (
              <TabsTrigger key={t} value={t}>
                {t}
              </TabsTrigger>
            ))}
          </TabsList>
          {data ? (
            <fieldset disabled={busy}>
              <TabsContent value="Providers">
                <Providers
                  data={data}
                  save={save}
                  toAccount={() => select("Account")}
                />
              </TabsContent>
              <TabsContent value="Models">
                <Models data={data} save={save} />
              </TabsContent>
              <TabsContent value="Account">
                <AccountPanel refresh={refresh} />
              </TabsContent>
              <TabsContent value="Advanced">
                <AdvancedPanel data={data} save={save} />
              </TabsContent>
              <TabsContent value="Appearance">
                <AppearancePanel data={data} save={save} />
              </TabsContent>
            </fieldset>
          ) : (
            <p role="status">
              {error ? "Settings unavailable." : "Loading settings…"}
            </p>
          )}
        </Tabs>
        {(error || busy || saved) && (
          <div className="settings-feedback">
            {error && (
              <div role="alert">
                {error}{" "}
                <Button
                  size="sm"
                  onClick={() => {
                    setError("");
                    refresh();
                  }}
                >
                  Refresh
                </Button>
              </div>
            )}
            {(busy || saved) && (
              <p role="status">{busy ? "Saving…" : "Saved."}</p>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
