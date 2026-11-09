import { Button } from "@pensarai/design-system/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@pensarai/design-system/ui/dialog";
import { Input } from "@pensarai/design-system/ui/input";
import { useEffect, useState } from "react";
import { api } from "../view/bridge";

export function ToolPicker({
  sessionId,
  disabled,
  open,
  onOpenChange,
}: {
  sessionId?: string;
  disabled?: boolean;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}) {
  const [localOpen, setLocalOpen] = useState(false);
  const [tools, setTools] = useState<{ name: string; enabled: boolean }[]>([]);
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const visible = open ?? localOpen;
  const changeOpen = onOpenChange ?? setLocalOpen;
  useEffect(() => {
    let current = true;
    if (sessionId && visible) {
      setTools([]);
      setError("");
      api
        .toolSelection({ id: sessionId })
        .then((rows) => {
          if (current) setTools(rows);
        })
        .catch((e) => {
          if (current) setError(String(e));
        });
    }
    return () => {
      current = false;
    };
  }, [sessionId, visible]);
  const toggle = async (name: string, enabled: boolean) => {
    if (!sessionId) return;
    setBusy(true);
    setError("");
    try {
      await api.setToolEnabled({ id: sessionId, name, enabled });
      setTools((rows) =>
        rows.map((row) => (row.name === name ? { name, enabled } : row)),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Button
        type="button"
        size="sm"
        onClick={() => changeOpen(true)}
        disabled={!sessionId || disabled}
      >
        Tools
      </Button>
      <Dialog open={visible && !!sessionId} onOpenChange={changeOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Session tools</DialogTitle>
            <DialogDescription>
              Choose the tools available on the next operator turn. The active
              mode can restrict this set further.
            </DialogDescription>
          </DialogHeader>
          <Input
            aria-label="Find a tool"
            placeholder="Find a tool"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {error && <p role="alert">{error}</p>}
          <div className="tool-list">
            {tools
              .filter((t) => t.name.includes(query.trim().toLowerCase()))
              .map((t) => (
                <label key={t.name}>
                  <input
                    type="checkbox"
                    disabled={disabled || busy}
                    checked={t.enabled}
                    onChange={(e) => toggle(t.name, e.target.checked)}
                  />
                  <span>{t.name}</span>
                </label>
              ))}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
