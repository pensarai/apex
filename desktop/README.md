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

Type `/` to search commands and discovered skills. Use ↑/↓ to select, Tab or Enter to insert, and Esc to dismiss. Selecting a command only inserts it; add arguments and send when ready. Project skills are available before the first message. Recognized command names at the start of the input appear green; mentions inside ordinary text keep the normal text color.

Use `/goal <objective> [--rounds N]` to start a persistent goal, `/goal` for status, and `/goal clear` (or **End goal**) to end it. The compact summary above the input expands to show the objective, rounds, completion evidence, and any blocker. Goals reuse the core evidence checks and continuation limits, wait for questions, approvals and plan reviews, and give queued messages priority. **Stop turn** interrupts work while preserving the goal; **Resume goal** continues it. Reopened sessions restore their goal without starting work until you resume or send a message. Internal continuation prompts stay out of the visible transcript. **Settings → Advanced** controls whether goals are enabled; Lance does not support them.

Drop files onto the message composer or use the paperclip to attach up to 10 files totaling 20 MB. Remove attachments with their × buttons before sending. Sending stores copies in the session directory and includes their paths in the message so the agent can inspect them with its file tools. Attachment-only messages are supported, and the copies remain available when the session is resumed. Attachments accompany ordinary messages, not slash commands.

While a turn is running, the send button becomes **Stop turn**; Enter still queues a follow-up. Hover or focus a running command row to **Cancel command** without stopping the turn. Click the model name (or use `/models`) to search configured models in a dropdown. Changes apply to the next turn. **Configure providers and models** opens settings for adding providers or custom models.

Slow commands can run as managed background jobs in local, unrecorded sessions. The agent sets `background: true` on `execute_command`, continues other work, and receives the result automatically when the command exits. A pill above the composer shows the running process count. Click it to open the resizable Processes sidebar with each command, live stdout, exit status, and a cancel action for operator jobs. Completed jobs remain visible while the sidebar is open. The command row also shows “Started in background” and its job ID. `command_job` inspects or cancels a job; **Stop turn** stops all jobs owned by that turn. Jobs retain their command timeout and do not survive closing the session or app.

`document_vulnerability` also uses the managed jobs system by default in local, unrecorded sessions. The calling agent or worker receives a job ID, continues independent work, then receives the final judge/scoring verdict automatically. The Processes sidebar shows the validation title, current stage (PoC, judging, scoring, or saving), and verdict. A receipt is not an accepted finding, and the agent cannot submit its structured final response while results are pending. Use `background: false` to wait synchronously; recorded and remote sessions keep synchronous validation.

The left sidebar lists open and recent saved sessions, with search and a **New session** button. Toggle it in the sidebar heading, reopen it from the left edge, or use ⌘B (Ctrl+B). Drag its right edge to resize it; the focused divider also supports arrow keys. Older saved sessions load as you scroll. New session reuses an existing empty tab and preserves its draft. A spinner indicates running work, a green dot indicates an unread assistant message, and a green **Needs input** pill indicates a pending question, approval, or plan review. Focusing a session clears its unread indicator; switching tabs preserves pending input requests.

Open **Attack surface** in a session to show a right sidebar alongside the conversation. Drag its left divider, or focus the divider and use the arrow keys, to resize it. Close it with its × button or Escape while focused inside the sidebar. The width is remembered while the session tab remains open. The first topology tool call, including calls from a recon subagent, opens the sidebar automatically. Once shown, it will not reopen automatically for that session, including after resuming it. Use it to inspect the boundaries, components, flows, controls, and threat scenarios documented during recon. The Graph view uses the Console system map’s nested boundaries, Internet routes, evidence line styles, and selection highlighting. Pan, zoom, or fit the map with the canvas controls; select a component or boundary to inspect its evidence. Inventory provides a searchable record list. The view refreshes while open and reads persisted session records, including updates and retired records, so the same map is available when you resume a session. Threat scenarios are hypotheses to verify, separate from confirmed findings.

Subagents appear beneath the tool call that started them, with status icons and links to their transcripts. Click a worker to open its messages in the conversation view; breadcrumbs return to its parent or the operator. Subagent transcripts are read-only, and returning to the operator restores your draft and conversation position. Older saved workers without parent-call metadata remain available in a separate Subagents list.

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
