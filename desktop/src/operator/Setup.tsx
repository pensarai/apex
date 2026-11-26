import { Button } from "@pensarai/design-system/ui/button";
import { Input } from "@pensarai/design-system/ui/input";
import { Textarea } from "@pensarai/design-system/ui/textarea";
import { useEffect, useState } from "react";
import type { SettingsSnapshot } from "../settings/contract";
import { api } from "../view/bridge";
import type { OperatorLaunch, OperatorMode } from "./contract";

export function OperatorSetup({
  start,
  busy,
  cancel,
  initial,
}: {
  start: (input: OperatorLaunch) => Promise<void>;
  busy: boolean;
  cancel?: () => void;
  initial?: OperatorLaunch;
}) {
  const [workflow, setWorkflow] = useState<
    "conversation" | "threat-model" | "prompt-injection"
  >(
    initial?.skill === "threat-model" || initial?.skill === "prompt-injection"
      ? initial.skill
      : "conversation",
  );
  const [error, setError] = useState("");
  const [headerMode, setHeaderMode] = useState(
    initial?.headers === undefined
      ? "default"
      : Object.keys(initial.headers).length
        ? "custom"
        : "none",
  );
  const credential = initial?.authCredentials?.[0];
  const [models, setModels] = useState<SettingsSnapshot["models"]>([]);
  useEffect(() => {
    let active = true;
    const load = () =>
      api
        .desktopSettings()
        .then((s) => {
          if (active) setModels(s.models);
        })
        .catch((e) => {
          if (active) setError(String(e));
        });
    void load();
    window.addEventListener("apex:settings", load);
    return () => {
      active = false;
      window.removeEventListener("apex:settings", load);
    };
  }, []);
  return (
    <form
      className="op-setup detail"
      onSubmit={async (e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const value = (key: string) => String(f.get(key) ?? "").trim();
        const ports = value("ports")
          .split(/[\s,]+/)
          .filter(Boolean)
          .map(Number);
        if (ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) {
          setError("Ports must be integers from 1 to 65535.");
          return;
        }
        setError("");
        const username = value("username"),
          password = String(f.get("password") ?? ""),
          apiKey = String(f.get("key") ?? ""),
          loginUrl = value("login");
        await start({
          mode: value("mode") as OperatorMode,
          target: value("target") || undefined,
          headers: headerMode === "none" ? {} : undefined,
          headerLines: headerMode === "custom" ? value("headers") : undefined,
          name: value("name") || undefined,
          model: value("model") || undefined,
          sandbox: value("directory") === "session",
          prompt: value("prompt") || undefined,
          skill: workflow === "conversation" ? undefined : workflow,
          skillOutput: value("output") || undefined,
          promptInjectionLibrarySource: value("library") || undefined,
          taskDriven: f.has("tasks"),
          ...(workflow !== "conversation" && {
            strikeMode: false,
            lanceMode: false,
          }),
          ...(value("profile") !== "default" && {
            strikeMode: value("profile") === "strike",
            lanceMode: value("profile") === "lance",
          }),
          scopeConstraints: {
            allowedHosts: value("hosts")
              .split(/[\s,]+/)
              .filter(Boolean),
            allowedPorts: ports,
            strictScope: f.has("strict"),
          },
          authCredentials:
            username || password || apiKey || loginUrl
              ? [{ username, password, apiKey, loginUrl }]
              : undefined,
          authenticationInstructions: value("instructions") || undefined,
        });
      }}
    >
      <fieldset disabled={busy}>
        <div className="op-fields">
          <label>
            Workflow
            <select
              value={workflow}
              onChange={(e) => setWorkflow(e.target.value as typeof workflow)}
            >
              <option value="conversation">Operator conversation</option>
              <option value="threat-model">Threat model</option>
              <option value="prompt-injection">Prompt-injection testing</option>
            </select>
          </label>
          <label>
            Mode
            <select name="mode" defaultValue={initial?.mode ?? "manual"}>
              <option value="manual">Manual approvals</option>
              <option value="auto">Automatic approvals</option>
              <option value="plan">Plan</option>
            </select>
          </label>
        </div>
        <label>
          Target
          <Input
            name="target"
            defaultValue={initial?.target}
            placeholder="Host or URL (optional)"
          />
        </label>
        {workflow === "conversation" && (
          <label>
            First message
            <Textarea
              name="prompt"
              defaultValue={initial?.prompt}
              rows={4}
              placeholder="What would you like to investigate?"
            />
          </label>
        )}
        {workflow === "threat-model" && (
          <label>
            Threat model output
            <Input
              name="output"
              defaultValue={initial?.skillOutput}
              placeholder="threat-model.md"
            />
          </label>
        )}
        {workflow === "prompt-injection" && (
          <label>
            Payload library
            <Input
              name="library"
              defaultValue={initial?.promptInjectionLibrarySource}
              placeholder="Local library path (optional)"
            />
          </label>
        )}
        <details>
          <summary>Session configuration</summary>
          <div className="op-fields">
            <label>
              Session name
              <Input name="name" defaultValue={initial?.name} />
            </label>
            <label>
              Model
              <select name="model" defaultValue={initial?.model ?? ""}>
                {initial?.model &&
                  !models.some((m) => m.id === initial.model) && (
                    <option value={initial.model}>{initial.model}</option>
                  )}
                <option value="">Settings default</option>
                {models.map((model) => (
                  <option key={model.id} value={model.id}>
                    {model.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Workspace
              <select
                name="directory"
                defaultValue={initial?.sandbox ? "session" : "workspace"}
              >
                <option value="workspace">Selected working directory</option>
                <option value="session">Session directory</option>
              </select>
            </label>
            {workflow === "conversation" && (
              <label>
                Operator profile
                <select name="profile">
                  <option value="default">Settings default</option>
                  <option value="standard">Standard</option>
                  <option value="strike">Strike</option>
                  <option value="lance">Lance</option>
                </select>
              </label>
            )}
            <label>
              Request headers
              <select
                value={headerMode}
                onChange={(e) => setHeaderMode(e.target.value)}
              >
                <option value="default">Workspace defaults</option>
                <option value="none">No custom headers</option>
                <option value="custom">Custom headers</option>
              </select>
            </label>
            {headerMode === "custom" && (
              <label>
                Headers, one per line
                <Textarea
                  name="headers"
                  defaultValue={Object.entries(initial?.headers ?? {})
                    .map(([k, v]) => `${k}: ${v}`)
                    .join("\n")}
                  placeholder="Name: value"
                  required
                />
              </label>
            )}
            <label className="op-check">
              <input
                type="checkbox"
                name="tasks"
                defaultChecked={initial?.taskDriven}
              />{" "}
              Task-driven session
            </label>
          </div>
        </details>
        <details>
          <summary>Scope and credentials</summary>
          <p>
            Target credentials are saved with this local session so it can be
            resumed.
          </p>
          <div className="op-fields">
            <label>
              Allowed hosts
              <Input
                name="hosts"
                defaultValue={initial?.scopeConstraints?.allowedHosts?.join(
                  ", ",
                )}
                placeholder="Comma-separated hosts"
              />
            </label>
            <label>
              Allowed ports
              <Input
                name="ports"
                defaultValue={initial?.scopeConstraints?.allowedPorts?.join(
                  ", ",
                )}
                placeholder="80, 443"
              />
            </label>
            <label className="op-check">
              <input
                type="checkbox"
                name="strict"
                defaultChecked={initial?.scopeConstraints?.strictScope}
              />{" "}
              Strict scope
            </label>
            <label>
              Login URL
              <Input
                name="login"
                defaultValue={credential?.loginUrl}
                type="url"
              />
            </label>
            <label>
              Username
              <Input
                name="username"
                defaultValue={credential?.username}
                autoComplete="off"
              />
            </label>
            <label>
              Password
              <Input
                name="password"
                defaultValue={credential?.password}
                type="password"
                autoComplete="new-password"
              />
            </label>
            <label>
              API key
              <Input
                name="key"
                defaultValue={credential?.apiKey}
                type="password"
                autoComplete="new-password"
              />
            </label>
            <label>
              Authentication instructions
              <Textarea
                name="instructions"
                defaultValue={initial?.authenticationInstructions}
              />
            </label>
          </div>
        </details>
        {error && <p role="alert">{error}</p>}
        <div className="actions">
          <Button type="submit" variant="constructive">
            {busy ? "Starting…" : "Start operator"}
          </Button>
          {cancel && (
            <Button type="button" onClick={cancel}>
              Back to conversation
            </Button>
          )}
        </div>
      </fieldset>
    </form>
  );
}
