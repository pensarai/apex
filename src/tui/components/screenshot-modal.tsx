import { open } from "node:fs/promises";
import { useKeyboard } from "@opentui/react";
import { useEffect, useState } from "react";
import { useDimensions } from "../context/dimensions";
import { useTheme } from "../theme";
import {
  deleteImage,
  kittyGraphicsSupported,
  moveCursor,
  nextImageId,
  transmitImageFromFile,
} from "../utils/kitty-graphics";
import type { DisplayMessage } from "./agent-display";
import { isToolMessage } from "./shared/type-guards";

// Layout reserves so the modal floats inside the chat region rather than
// covering header / input. These match the operator dashboard's flex
// structure (header bar ~3-4 rows; input area + status bar ~6 rows).
const HEADER_ROWS = 4;
const FOOTER_ROWS = 6;

// Browser screenshots are PNG. Read width/height from the IHDR chunk
// (BE uint32 at byte offsets 16 and 20) instead of pulling in `sharp`,
// whose native addon can't be embedded by `bun build --compile`.
async function readPngDimensions(
  path: string,
): Promise<{ width: number; height: number }> {
  const fh = await open(path, "r");
  try {
    const buf = Buffer.alloc(24);
    await fh.read(buf, 0, 24, 0);
    if (
      buf.readUInt32BE(0) !== 0x89504e47 ||
      buf.readUInt32BE(4) !== 0x0d0a1a0a
    ) {
      throw new Error("not a PNG");
    }
    return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
  } finally {
    await fh.close();
  }
}

interface Props {
  /** Chronological list (oldest -> newest). */
  screenshots: string[];
  /** Defaults to the newest. */
  initialIndex?: number;
  onClose: () => void;
}

/**
 * Walk a DisplayMessage list and return host-fs paths for every
 * completed `browser_screenshot` tool result, in source order.
 */
export function collectScreenshotPaths(messages: DisplayMessage[]): string[] {
  const paths: string[] = [];
  for (const m of messages) {
    if (!isToolMessage(m)) continue;
    if (m.toolName !== "browser_screenshot") continue;
    if (m.status !== "completed") continue;
    const r = m.result;
    if (typeof r !== "object" || r === null) continue;
    const obj = r as Record<string, unknown>;
    if (obj.success !== true) continue;
    if (typeof obj.path !== "string") continue;
    paths.push(obj.path);
  }
  return paths;
}

/**
 * Stack-aware screenshot viewer. Renders the current PNG via the kitty
 * graphics protocol, centered inside the chat region. Left/right arrows
 * skim through the stack; any other key closes.
 *
 * Falls back to a "graphics not supported" notice if the terminal can't
 * do kitty graphics — arrows still navigate, but the path is shown as
 * text.
 */
export function ScreenshotModal({ screenshots, initialIndex, onClose }: Props) {
  const { width: termW, height: termH } = useDimensions();
  const { colors } = useTheme();
  const supported = kittyGraphicsSupported();

  const safeInitial = Math.min(
    Math.max(0, initialIndex ?? screenshots.length - 1),
    Math.max(0, screenshots.length - 1),
  );
  const [index, setIndex] = useState(safeInitial);
  const path = screenshots[index];
  const total = screenshots.length;

  useKeyboard((key) => {
    if (key.name === "left") {
      key.preventDefault?.();
      setIndex((i) => Math.max(0, i - 1));
      return;
    }
    if (key.name === "right") {
      key.preventDefault?.();
      setIndex((i) => Math.min(total - 1, i + 1));
      return;
    }
    onClose();
  });

  useEffect(() => {
    if (!supported || !path) return;
    let cancelled = false;
    const id = nextImageId();
    (async () => {
      try {
        const { width: w, height: h } = await readPngDimensions(path);
        // Available cell box inside the chat region (reserve header /
        // footer so they stay visible). Cells are ~1:2 on screen, so
        // image cell-aspect = (h/w) / 2.
        const availCols = Math.max(4, termW - 4);
        const availRows = Math.max(4, termH - HEADER_ROWS - FOOTER_ROWS);
        const imgCellAspect = h / w / 2;
        const boxCellAspect = availRows / availCols;
        let cols: number;
        let rows: number;
        if (imgCellAspect > boxCellAspect) {
          rows = availRows;
          cols = Math.max(2, Math.floor(rows / imgCellAspect));
        } else {
          cols = availCols;
          rows = Math.max(2, Math.floor(cols * imgCellAspect));
        }
        if (cancelled) return;
        // 1-indexed cursor; center horizontally in termW, vertically in
        // the chat region (between HEADER_ROWS and termH - FOOTER_ROWS).
        const xCell = Math.max(1, Math.floor((termW - cols) / 2) + 1);
        const yCell = Math.max(
          HEADER_ROWS + 1,
          HEADER_ROWS + Math.floor((availRows - rows) / 2) + 1,
        );
        moveCursor(yCell, xCell);
        transmitImageFromFile({ path, columns: cols, rows, imageId: id });
      } catch {
        // ignore — modal stays open with backdrop only
      }
    })();
    return () => {
      cancelled = true;
      deleteImage(id);
    };
  }, [path, termW, termH, supported]);

  // Controls hint sits one row below the reserved chat region so it
  // never overlaps the image. Always show esc; show ← → only when there
  // are multiple screenshots to skim.
  const counter = `${index + 1} / ${total}`;
  const controls =
    total > 1
      ? `← →  navigate · esc  close · ${counter}`
      : `esc  close · ${counter}`;
  const indicatorRow = Math.max(0, termH - FOOTER_ROWS);

  return (
    <box
      position="absolute"
      top={0}
      left={0}
      width={termW}
      height={termH}
      backgroundColor={colors.background}
      onMouseDown={(e: { stopPropagation: () => void }) => {
        e.stopPropagation();
        onClose();
      }}
    >
      {!supported && path && (
        <box
          position="absolute"
          top={HEADER_ROWS}
          left={0}
          width={termW}
          height={Math.max(4, termH - HEADER_ROWS - FOOTER_ROWS)}
          flexDirection="column"
          alignItems="center"
          justifyContent="center"
        >
          <text fg={colors.text}>
            Terminal does not support kitty graphics protocol.
          </text>
          <text fg={colors.textMuted}>{path}</text>
          <text fg={colors.textMuted}>(any key to close)</text>
        </box>
      )}
      <box
        position="absolute"
        top={indicatorRow}
        left={0}
        width={termW}
        flexDirection="row"
        justifyContent="center"
      >
        <text fg={colors.textMuted}>{controls}</text>
      </box>
    </box>
  );
}
