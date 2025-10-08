# Apex - OpenTUI Application

A terminal UI application built with [OpenTUI](https://github.com/thecodrr/opentui) and React.

## Setup

Install dependencies:

```bash
bun install
```

## Development

Run with hot reloading (auto-restarts on file changes):

```bash
bun run dev
```

Run once (no hot reloading):

```bash
bun start
```

## Features

- **Command System**: Extensible command router with autocomplete
- **Hotkeys**:
  - `Tab` / `Shift+Tab`: Navigate between UI elements
  - `Ctrl+C`: Clear input (press twice to exit)
  - `↑` / `↓`: Navigate autocomplete suggestions
  - `Esc`: Close dialogs
- **Commands**:
  - `/help` or `?`: Show help dialog
  - Autocomplete shows available commands as you type

## Project Structure

```
src/
├── index.tsx           # Main application
├── components/         # UI components
│   ├── alert-dialog.tsx
│   ├── autocomplete.tsx
│   ├── footer.tsx
│   ├── header.tsx
│   └── input.tsx
├── command-router.ts   # Command system
└── ascii-art.tsx       # ASCII art utilities
```

---

Built with [Bun](https://bun.com) and [OpenTUI](https://github.com/thecodrr/opentui).
