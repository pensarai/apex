/**
 * Kitty graphics protocol bindings.
 *
 * Writes APC escape sequences directly to stdout. Images live in a separate
 * terminal layer from the cell grid (opentui owns the cell grid; we own the
 * graphics layer). The terminal composites the two — image z-index controls
 * stacking. We use z >= 1 so images sit above text.
 *
 * Protocol reference: https://sw.kovidgoyal.net/kitty/graphics-protocol/
 */

const APC = "\x1b_G";
const ST = "\x1b\\";

let nextId = 1;

/**
 * Heuristic: is the terminal likely to support the kitty graphics protocol?
 * Covers kitty, ghostty, wezterm, and iTerm (which also supports kitty).
 *
 * False here means callers should fall back to the cell-grid quarter-block
 * preview rather than open a graphics modal.
 */
export function kittyGraphicsSupported(): boolean {
  const term = process.env.TERM ?? "";
  const program = process.env.TERM_PROGRAM ?? "";
  return (
    term.includes("kitty") ||
    term.includes("ghostty") ||
    program === "ghostty" ||
    program === "kitty" ||
    program === "WezTerm" ||
    program === "iTerm.app"
  );
}

/**
 * Allocate a unique image ID. The terminal uses this to track and later
 * delete the image.
 */
export function nextImageId(): number {
  return nextId++;
}

/**
 * Transmit a PNG file (by path) to the terminal and display it at the
 * current cursor position, sized to (columns × rows) cells.
 *
 * Uses t=f (file transmission) so the terminal reads the PNG from disk —
 * no base64 chunking needed. The path is base64-encoded as the payload.
 */
export function transmitImageFromFile(opts: {
  path: string;
  columns: number;
  rows: number;
  imageId: number;
  zIndex?: number;
}): void {
  const { path, columns, rows, imageId, zIndex = 10 } = opts;
  const payload = Buffer.from(path).toString("base64");
  const ctrl = `f=100,t=f,a=T,c=${columns},r=${rows},z=${zIndex},q=2,i=${imageId}`;
  process.stdout.write(`${APC}${ctrl};${payload}${ST}`);
}

/** Delete a single image by ID. */
export function deleteImage(imageId: number): void {
  process.stdout.write(`${APC}a=d,d=I,i=${imageId},q=2;${ST}`);
}

/**
 * Move the cursor (1-indexed). The next graphics transmit anchors the
 * image's top-left at this position.
 */
export function moveCursor(row: number, col: number): void {
  process.stdout.write(`\x1b[${row};${col}H`);
}
