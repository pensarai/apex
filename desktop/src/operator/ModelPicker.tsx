import { Button } from "@pensarai/design-system/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@pensarai/design-system/ui/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@pensarai/design-system/ui/popover";
import { Check, ChevronDown, Settings2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { SettingsModel, SettingsSnapshot } from "../settings/contract";
import { api } from "../view/bridge";

type Catalog = Pick<SettingsSnapshot, "models" | "selected" | "catalogError">;

export function ModelPicker({
  models,
  selected,
  current,
  active = false,
  open,
  onOpenChange,
  onSettings,
  onSelectModel,
}: {
  models?: SettingsModel[];
  selected?: string;
  current?: string;
  active?: boolean;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSettings?: () => void;
  onSelectModel?: (id: string) => Promise<void>;
}) {
  const [catalog, setCatalog] = useState<Catalog>({
    models: models ?? [],
    selected,
  });
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState<string>();
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [refresh, setRefresh] = useState(0);
  const request = useRef(0);
  const writing = useRef(false);
  const mounted = useRef(true);

  useEffect(() => {
    setCatalog((previous) => ({ ...previous, models: models ?? [], selected }));
  }, [models, selected]);
  useEffect(() => {
    mounted.current = true;
    const changed = (event: Event) => {
      request.current++;
      const next = (event as CustomEvent<SettingsSnapshot>).detail;
      setCatalog(next);
      setLoading(false);
    };
    window.addEventListener("apex:settings", changed);
    return () => {
      mounted.current = false;
      request.current++;
      window.removeEventListener("apex:settings", changed);
    };
  }, []);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Refresh is an explicit catalog invalidation signal.
  useEffect(() => {
    if (!open) return;
    const revision = ++request.current;
    setLoading(true);
    setError("");
    setQuery("");
    void api
      .desktopSettings()
      .then((next) => {
        if (request.current === revision) setCatalog(next);
      })
      .catch((failure) => {
        if (request.current === revision) setError(String(failure));
      })
      .finally(() => {
        if (request.current === revision) setLoading(false);
      });
    return () => {
      request.current++;
    };
  }, [open, refresh]);

  const groups = useMemo(() => {
    const providers = new Map<string, SettingsModel[]>();
    for (const model of catalog.models) {
      const group = providers.get(model.provider) ?? [];
      group.push(model);
      providers.set(model.provider, group);
    }
    return [...providers];
  }, [catalog.models]);
  const displayedId = active
    ? (current ?? catalog.selected)
    : (catalog.selected ?? current);
  const displayed =
    catalog.models.find((model) => model.id === displayedId) ??
    models?.find((model) => model.id === displayedId);

  const choose = async (id: string) => {
    if (writing.current) return;
    if (id === catalog.selected && !onSelectModel) {
      onOpenChange(false);
      return;
    }
    writing.current = true;
    request.current++;
    setLoading(false);
    setSaving(id);
    setError("");
    try {
      const next = await api.changeSettings({ kind: "model", id });
      window.dispatchEvent(new CustomEvent("apex:settings", { detail: next }));
      await onSelectModel?.(id);
      if (mounted.current) onOpenChange(false);
    } catch (failure) {
      if (mounted.current) setError(String(failure));
    } finally {
      writing.current = false;
      if (mounted.current) setSaving(undefined);
    }
  };

  return (
    <Popover open={open} onOpenChange={onOpenChange}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="op-model"
          aria-label="Select model"
          title={displayedId}
        >
          {displayed?.provider && (
            <span className="op-model-provider">{displayed.provider} / </span>
          )}
          {displayed?.name || displayedId || "Select model"}
          <ChevronDown size={12} aria-hidden="true" />
        </button>
      </PopoverTrigger>
      <PopoverContent
        side="top"
        align="start"
        className="op-model-picker"
        aria-label="Choose model"
      >
        <Command label="Models" loop>
          <CommandInput
            placeholder="Search models or providers…"
            aria-label="Search models"
            value={query}
            onValueChange={setQuery}
          />
          {active && (
            <p className="op-model-picker-status">
              Changes apply to your next turn.
            </p>
          )}
          {error && (
            <div className="op-model-picker-status" role="alert">
              {error}
              <Button
                size="xs"
                variant="ghost"
                disabled={!!saving}
                onClick={() => setRefresh((value) => value + 1)}
              >
                Refresh models
              </Button>
            </div>
          )}
          {catalog.catalogError && (
            <p className="op-model-picker-status" role="alert">
              {catalog.catalogError}
            </p>
          )}
          <CommandList
            aria-label="Available models"
            aria-busy={loading || !!saving}
          >
            <CommandEmpty>
              {loading
                ? "Loading models…"
                : catalog.models.length
                  ? "No matching models."
                  : "Configure a provider to add models."}
            </CommandEmpty>
            {groups.map(([provider, entries]) => (
              <CommandGroup key={provider} heading={provider}>
                {entries.map((model) => (
                  <CommandItem
                    key={model.id}
                    value={model.id}
                    keywords={[model.name, model.provider]}
                    className="op-model-option"
                    disabled={!!saving}
                    onSelect={() => void choose(model.id)}
                    aria-label={`${model.provider} / ${model.name}`}
                  >
                    <span className="op-model-option-copy">
                      <span>{model.name}</span>
                      <span className="op-model-option-id">{model.id}</span>
                    </span>
                    {saving === model.id ? (
                      <span className="op-model-selected">Saving…</span>
                    ) : catalog.selected === model.id ? (
                      <Check
                        className="op-model-selected"
                        size={14}
                        aria-label="Selected model"
                      />
                    ) : null}
                  </CommandItem>
                ))}
              </CommandGroup>
            ))}
          </CommandList>
        </Command>
        {onSettings && (
          <div className="op-model-picker-footer">
            <Button
              size="sm"
              variant="ghost"
              disabled={!!saving}
              onClick={() => {
                onOpenChange(false);
                onSettings();
              }}
            >
              <Settings2 size={14} /> Configure providers and models
            </Button>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}
