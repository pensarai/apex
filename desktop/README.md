# Apex Desktop

A local desktop client for Apex, built with Electrobun, Bun, React and the Pensar design system. The webview talks to the Bun host through typed RPC. The host uses the same agent APIs, approval gate, configuration, sessions and recorded-run store as the TUI.

## Run from source

Use Bun 1.3 and Node 22. Install the root dependencies, then install the desktop package with read access to `@pensarai/design-system` on GitHub Packages. With a GitHub CLI login that has `read:packages`, run these commands from the repository root.

```sh
bun install --frozen-lockfile
GITHUB_PACKAGES_TOKEN="$(gh auth token)" bun install --cwd desktop --frozen-lockfile
bun run desktop
```

The app opens directly to **Operator**. Send a message to start chatting, or change the working directory below the composer. The **Apex** menu (⌘K on macOS, Ctrl+K elsewhere) contains **Pentest**, **Sessions**, **Recorded runs**, **Terminal**, **Skills**, and **Settings**. **Settings** manages the same providers, model preferences and account as the TUI. New installations open provider settings after the responsible-use disclosure.

Operator uses the selected working directory and saved model defaults. Enter sends a message, Shift+Enter adds a line, and Shift+Tab cycles Manual, Automatic and Plan modes. Use **New session**, ⌘N (Ctrl+N), or `/new` for a fresh tab, `/help` for commands, and **Details** to inspect the session.

Drag tabs to reorder them, or drop a tab on the left or right of the conversation area to dock two sessions side by side. The **Arrange sessions** menu provides the same actions by keyboard. Drag the divider to resize the panes, use its arrow keys, or double-click to reset it. Each session keeps its draft, transcript, working directory, approvals and running turn when you switch tabs. Closing a running session asks you to stop it first; saved conversations remain available in **Sessions**. The tab layout lasts for the current app run.

**Recorded runs** connects to the SDK’s local worker store. Detached workers survive closing the window. **Terminal** runs the bundled TUI in the selected directory.

## Build and verify

From the repository root:

```sh
bun run --cwd desktop check
bun run test
bun test desktop/src/settings/settings.bun.test.tsx
bun run --cwd desktop build
```

Electrobun writes the development application to `desktop/build/dev-<platform>-<arch>/`. Build on the target OS. The CLI and detached workers use the app’s bundled Bun runtime. Apex’s browser tools use Node and fetch the browser on demand, as they do in the TUI.
