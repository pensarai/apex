import { Button } from "@pensarai/design-system/ui/button";
import { Input } from "@pensarai/design-system/ui/input";
import {
  NativeSelect,
  NativeSelectOption,
} from "@pensarai/design-system/ui/native-select";
import { Textarea } from "@pensarai/design-system/ui/textarea";
import { useEffect, useState } from "react";
import { api } from "./bridge";

export function NewRun({
  cwd,
  store,
  done,
  cancel,
}: {
  cwd: string;
  store?: string;
  done: (id: string) => void;
  cancel: () => void;
}) {
  const [defaults, setDefaults] =
    useState<Awaited<ReturnType<typeof api.desktopSettings>>>();
  useEffect(() => {
    let active = true;
    api
      .desktopSettings()
      .then((d) => {
        if (active) setDefaults(d);
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [id] = useState(() => `run_${crypto.randomUUID()}`);
  const start = async (getSpec: () => Promise<string> | string) => {
    setBusy(true);
    setError("");
    try {
      done(await api.startRun({ spec: await getSpec(), store }));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      className="detail run-form"
      onSubmit={(e) => {
        e.preventDefault();
        const data = new FormData(e.currentTarget);
        void start(() => {
          const target = new URL(String(data.get("target")));
          if (!["https:", "http:"].includes(target.protocol))
            throw new Error("Use an HTTP or HTTPS target.");
          return JSON.stringify({
            schemaVersion: 1,
            configVersion: 1,
            runId: id,
            model: String(data.get("model")).trim(),
            target: target.href,
            prompt: String(data.get("prompt")).trim(),
            activeTools: ["http_request", "document_vulnerability"],
            environment: { kind: "local", cwd },
            scope: {
              version: 1,
              strictScope: true,
              allowedHosts: [target.hostname],
              allowedPorts: [
                Number(
                  target.port || (target.protocol === "https:" ? 443 : 80),
                ),
              ],
            },
            approval: { requiredTools: ["http_request"] },
          });
        });
      }}
    >
      <h2>New recorded run</h2>
      <fieldset disabled={busy}>
        <label>
          Target URL
          <Input
            name="target"
            placeholder="https://app.example.com"
            type="url"
            required
          />
        </label>
        <label>
          Model
          <NativeSelect
            required
            name="model"
            key={defaults?.selected}
            defaultValue={defaults?.selected}
          >
            <NativeSelectOption value="">
              Select a configured model
            </NativeSelectOption>
            {defaults?.models.map((model) => (
              <NativeSelectOption value={model.id} key={model.id}>
                {model.name} · {model.provider}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        </label>
        <label>
          Objective
          <Textarea
            name="prompt"
            rows={4}
            required
            placeholder="What should the agent investigate?"
          />
        </label>
        <p>
          HTTP requests require your approval and are scoped to the target host
          and port. The agent can document findings.
        </p>
        <div className="actions">
          <Button type="submit" variant="constructive">
            {busy ? "Starting…" : "Start run"}
          </Button>
          <Button type="button" onClick={cancel}>
            Cancel
          </Button>
        </div>
        <label className="import">
          Start from an existing JSON run spec
          <input
            type="file"
            accept=".json,application/json"
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.target.value = "";
              if (file) void start(() => file.text());
            }}
          />
        </label>
      </fieldset>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}
