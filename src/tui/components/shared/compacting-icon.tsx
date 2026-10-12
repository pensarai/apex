import type { RGBA } from "@opentui/core";
import { useEffect, useState } from "react";

const FRAMES = ["[====]", "[=== ]", "[==  ]", "[=   ]"];

export function CompactingIcon({ fg }: { fg: RGBA }) {
  const [frame, setFrame] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setFrame((current) => (current + 1) % FRAMES.length);
    }, 180);
    return () => clearInterval(interval);
  }, []);

  return <text fg={fg}>{FRAMES[frame]}</text>;
}
