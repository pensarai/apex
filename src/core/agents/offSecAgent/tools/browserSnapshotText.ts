/**
 * First-observation cap for `browser_snapshot`.
 *
 * Tool-result compaction truncates results only once a later fit runs.
 * A snapshot is the tool result itself, so an uncapped accessibility tree
 * (a full Google or AuthKit DOM) enters the transcript on the next model
 * step and can fill the window before that fit exists.
 *
 * Form controls are kept ahead of structural lines and generic nodes so a
 * login field that sits late in the tree is still visible.
 */
export const BROWSER_SNAPSHOT_MAX_CHARS = 24_000;

const FORM_CONTROL =
  /\] (button|textbox|checkbox|radio|combobox|listbox|searchbox|slider|spinbutton|switch|option)\b/;
const STRUCTURE = /\] (heading|link|tab|menuitem|form|navigation)\b/;

export function capBrowserSnapshot(text: string): string {
  if (text.length <= BROWSER_SNAPSHOT_MAX_CHARS) return text;
  const lines = text.split("\n");
  const rank = lines.map((line) => {
    if (FORM_CONTROL.test(line)) return 0;
    if (STRUCTURE.test(line)) return 1;
    return 2;
  });
  const keep = new Array<boolean>(lines.length).fill(false);
  let used = 0;
  const noteReserve = 64;
  const limit = BROWSER_SNAPSHOT_MAX_CHARS - noteReserve;
  for (const wanted of [0, 1, 2]) {
    for (let i = 0; i < lines.length; i++) {
      if (keep[i] || rank[i] !== wanted) continue;
      const addition = lines[i].length + (used > 0 ? 1 : 0);
      if (used + addition > limit) continue;
      keep[i] = true;
      used += addition;
    }
  }
  const kept: string[] = [];
  let omitted = 0;
  for (let i = 0; i < lines.length; i++) {
    if (keep[i]) kept.push(lines[i]);
    else omitted++;
  }
  if (kept.length === 0) {
    return `${lines[0].slice(0, limit)}\n…[snapshot truncated]`;
  }
  return `${kept.join("\n")}\n…[snapshot truncated, ${omitted} lines omitted]`;
}
