export function installAgentCursor() {
  const state = window as unknown as {
    __apexAgentCursor?: (enabled: boolean) => void;
  };
  if (state.__apexAgentCursor) return;
  let enabled = false;
  let cursor: HTMLDivElement | undefined;
  state.__apexAgentCursor = (value) => {
    enabled = value;
    if (cursor) cursor.style.opacity = "0";
  };
  const show = (x: number, y: number) => {
    if (!enabled || !document.documentElement) return;
    if (!cursor) {
      cursor = document.createElement("div");
      cursor.setAttribute("aria-hidden", "true");
      cursor.style.cssText =
        "position:fixed;z-index:2147483647;pointer-events:none;left:0;top:0;color:#00c865;transition:opacity 180ms;filter:drop-shadow(0 1px 2px #0006)";
      cursor.innerHTML =
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" stroke="#111" stroke-width="1"><path d="m3 3 7 18 3-8 8-3Z"/></svg><span style="display:block;margin:-3px 0 0 16px;padding:2px 6px;background:#00c865;color:#101010;font:11px monospace">Apex</span>';
      document.documentElement.append(cursor);
    }
    cursor.style.transform = `translate(${x}px, ${y}px)`;
    cursor.style.opacity = "1";
  };
  document.addEventListener(
    "pointermove",
    (event) => show(event.clientX, event.clientY),
    true,
  );
  document.addEventListener(
    "pointerdown",
    (event) => show(event.clientX, event.clientY),
    true,
  );
  document.addEventListener(
    "focusin",
    (event) => {
      const box = (event.target as Element | null)?.getBoundingClientRect();
      if (box) show(box.x + box.width / 2, box.y + box.height / 2);
    },
    true,
  );
}
export function enableAgentCursor(enabled: boolean) {
  (
    window as unknown as { __apexAgentCursor?: (enabled: boolean) => void }
  ).__apexAgentCursor?.(enabled);
}
