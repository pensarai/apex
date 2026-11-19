import { Button } from "@pensarai/design-system/ui/button";
import { Check, Copy } from "lucide-react";
import { useEffect, useState } from "react";

export function MessageCopy({ text }: { text: string }) {
  const [status, setStatus] = useState<"idle" | "copying" | "copied" | "error">(
    "idle",
  );
  useEffect(() => {
    if (status !== "copied") return;
    const timer = window.setTimeout(() => setStatus("idle"), 1600);
    return () => window.clearTimeout(timer);
  }, [status]);
  const copy = async () => {
    setStatus("copying");
    try {
      await navigator.clipboard.writeText(text);
      setStatus("copied");
    } catch {
      setStatus("error");
    }
  };
  return (
    <div
      className="op-message-actions"
      data-feedback={status === "copied" || status === "error"}
    >
      <Button
        size="xs"
        variant="ghost"
        aria-label="Copy message"
        title={
          status === "error" ? "Copy failed. Click to retry." : "Copy message"
        }
        disabled={status === "copying"}
        onClick={() => void copy()}
      >
        {status === "copied" ? (
          <Check size={12} aria-hidden="true" />
        ) : (
          <Copy size={12} aria-hidden="true" />
        )}
        <span role="status">
          {status === "copied"
            ? "Copied"
            : status === "error"
              ? "Retry copy"
              : "Copy"}
        </span>
      </Button>
    </div>
  );
}
