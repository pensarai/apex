# Apex Desktop

A local desktop client for Apex, built with Electrobun, Bun, React and the Pensar design system. The webview talks to the Bun host through typed RPC. The host uses the same agent APIs, approval gate, configuration, sessions and recorded-run store as the TUI.

## Run from source

Use Bun 1.3 and Node 22. Install the root dependencies, then install the desktop package with read access to `@pensarai/design-system` on GitHub Packages. With a GitHub CLI login that has `read:packages`, run these commands from the repository root.

```sh
bun install --frozen-lockfile
GITHUB_PACKAGES_TOKEN="$(gh auth token)" bun install --cwd desktop --frozen-lockfile
bun run desktop
```

Choose the working directory in the sidebar. Open **Operator** to create an interactive session, **Pentest** to configure an autonomous engagement, or **Sessions** to resume one. **Settings** manages the same providers, model preferences and account as the TUI. New installations open provider settings after the responsible-use disclosure.

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
