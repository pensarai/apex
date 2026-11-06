import type { RGBA } from "@opentui/core";
import { useEffect, useState } from "react";

// Adapted from throbber-widgets ASCII (MIT); local to avoid its react-dom peer.
const FRAMES = ["|", "/", "-", "\\"].map((frame) => `[${frame}]`);

export function ModelLoadingIcon({ fg }: { fg: RGBA }) {
  const [frame, setFrame] = useState(0);
  useEffect(() => {
    const timer = setInterval(
      () => setFrame((f) => (f + 1) % FRAMES.length),
      120,
    );
    return () => clearInterval(timer);
  }, []);
  return (
    <text fg={fg} flexShrink={0}>
      {FRAMES[frame]}
    </text>
  );
}
