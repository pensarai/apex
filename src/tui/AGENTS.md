# AGENTS.md — `src/tui/`

Rules for the terminal UI. The root [`AGENTS.md`](../../AGENTS.md) still applies.

## UI/UX conventions

**Reuse shared components.** Before building inline UI for controls, indicators, or dialog chrome, check `src/tui/components/shared/` for existing components. If you see the same pattern implemented inline in 2+ places, extract it into a shared component rather than duplicating it — duplication is how conventions silently diverge.

**Dialog shortcut controls.** Use the `DialogControls` component (`src/tui/components/shared/dialog-controls.tsx`) for keyboard hint bars at the bottom of dialogs. It supports three variants: `default` (muted — for secondary actions), `primary` (bright — for the main CTA), and `danger` (red — for irreversible actions like Delete/Disconnect). Ordering: primary action first, secondary actions next, danger actions after, Esc always last. `[Esc] Close` is rendered automatically by the `Dialog` component's top-right chrome — don't add it to the controls array. Only show non-obvious shortcuts; intuitive actions like ↑/↓ navigation don't need hints. Key capitalization: Title Case for named keys (`Enter`, `Esc`, `Tab`), uppercase for single letters (`D`, `R`, `M`), arrows as `↑/↓`.

**Consistency over novelty.** When adding a new dialog or view, match the patterns of existing ones. Don't invent new shortcut formatting, separator styles, color schemes, or layouts. Open a few existing dialogs as reference before starting — small inconsistencies compound quickly across a codebase.

**Dialogs, not routes.** Commands that show supplementary information (settings, model selection, help, credits, skills) must open as dialog overlays, not full-page route navigation. Full-page routes break the user's context and are reserved for primary workflows (pentest, operator mode). Use the `DialogLayout` component for consistent structure.

**Terminal size resilience.** Layouts must degrade gracefully on small terminals. All text containers must set `overflow="hidden"`. Fixed-height elements (headers, footers, control bars) must use `flexShrink={0}`. Use terminal dimensions (`stdout.columns`, `stdout.rows`) to compute available space and hide non-essential decorative elements (animations, verbose help text) when space is tight. Never assume a minimum terminal size.

**Theme-aware colors.** All color values must respect the current `ColorMode` (dark/light). Never hardcode RGBA values for a single theme. Use dual-palette maps keyed by `ColorMode` (see `components/shared/syntax-highlight.ts` for the pattern). This applies to syntax highlighting, status indicators, and any styled text output.

**Stable React keys.** Never include mutable content (message text, streaming output) in React `key` props. Use stable identifiers like `role + timestamp`, tool call IDs, or array indices. Content-derived keys cause unmount/remount on every frame during streaming, which resets scroll position and causes visual flicker.

**No state toggling in streaming callbacks.** Avoid calling `setState` to toggle visual indicators (like "Thinking...") directly in high-frequency streaming callbacks (`onTextDelta`, `onToolCallStreaming`). This causes per-frame flicker. Instead, derive display state from the underlying data model (e.g., check if the last message is a tool result rather than toggling a boolean).

**Scrollbars.** Don't pass `scrollbarOptions={{ visible: true }}` — opentui auto-shows the bar when content overflows the viewport and hides it otherwise. Forcing `visible: true` paints a full-track thumb when content fits, which reads as a stray colored block. Style with `trackOptions: { foregroundColor: colors.textMuted, backgroundColor: colors.backgroundElement }` so the thumb stays subtle and theme-aware (don't use `colors.primary` — too loud). Never explicitly hide scrollbars in scrollable regions.
