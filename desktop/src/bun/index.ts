import { access, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import Electrobun, {
  ApplicationMenu,
  BrowserView,
  BrowserWindow,
  PATHS,
  Utils,
} from "electrobun/bun";
import { version } from "../../../package.json";
import { parseRecordedRunsArgs } from "../../../src/core/cli/recordedRunsArgs";
import { config } from "../../../src/core/config";
import { hasAnyProviderConfigured } from "../../../src/core/providers";
import { sessions } from "../../../src/core/session";
import { createSkillsRegistry } from "../../../src/core/skills";
import { nativeBrowserBridge } from "../browser/native";
import { splitCommand } from "../commands";
import { toolRequests } from "../operator/tools";
import { createOperatorWorkspace } from "../operator/workspace-host";
import { createPentestRequests } from "../pentest/host";
import { createSettingsHost } from "../settings/host";
import type { DesktopRPC } from "../shared";
import { createFileRequests } from "./files";
import {
  openRuns,
  sessionArtifacts,
  sessionId,
  sessionRows,
} from "./workspace";

await import("../browser/native-runtime");
if (process.platform === "darwin") await import("../browser/native-macos");

const cli = join(PATHS.RESOURCES_FOLDER, "app", "cli", "cli.js");
const url = "views://workspace/index.html";
let cwd = homedir();
let accepted = false;
let watching: { key: string; controller: AbortController } | undefined;
let child: Bun.Subprocess | undefined;
async function withRuns<T>(
  store: string | undefined,
  fn: (client: Awaited<ReturnType<typeof openRuns>>) => Promise<T>,
): Promise<T> {
  const client = await openRuns(
    { command: process.execPath, args: [cli] },
    store,
  );
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}
function requireAcceptance() {
  if (!accepted) throw new Error("Accept the responsible use policy first.");
}
function validSize({ cols, rows }: { cols: number; rows: number }) {
  return (
    Number.isInteger(cols) &&
    cols >= 2 &&
    cols <= 1000 &&
    Number.isInteger(rows) &&
    rows >= 1 &&
    rows <= 1000
  );
}

const operator = createOperatorWorkspace({
  nativeBrowser: nativeBrowserBridge({
    getView: (id) => BrowserView.getById(id),
    windowId: () => mainWindow.id,
  }),
  cwd: () => cwd,
  requireAcceptance,
  emit: (snapshot) => rpc.send.operatorSnapshot(snapshot),
  emitBrowser: (event) => rpc.send.operatorBrowser(event),
});
const pentest = createPentestRequests({
  getCwd: () => cwd,
  requireAcceptance,
  startOperator: (input) => operator.start(input),
});
const settings = createSettingsHost({
  requireAcceptance,
  openExternal: (url) => {
    if (!Utils.openExternal(url))
      throw new Error("The browser could not open the requested page.");
  },
});
const skills = createSkillsRegistry();
const rpc = BrowserView.defineRPC<DesktopRPC>({
  maxRequestTime: 60_000,
  handlers: {
    requests: {
      ...toolRequests,
      ...operator.requests,
      ...pentest,
      ...settings.requests,
      windowAction: ({ action }): void => {
        switch (action) {
          case "close":
            mainWindow.close();
            break;
          case "minimize":
            mainWindow.minimize();
            break;
          case "toggle-maximize":
            if (mainWindow.isMaximized()) mainWindow.unmaximize();
            else mainWindow.maximize();
            break;
        }
      },
      workspace: async () => {
        const current = await config.get();
        accepted = current.responsibleUseAccepted;
        return {
          cwd,
          version,
          accepted,
          hasProvider: hasAnyProviderConfigured(current),
        };
      },
      chooseFolder: async () => {
        if (child)
          throw new Error("Exit the active terminal before changing folders.");
        const [folder] = await Utils.openFileDialog({
          startingFolder: cwd,
          canChooseFiles: false,
          canChooseDirectory: true,
          allowsMultipleSelection: false,
        });
        if (folder) cwd = folder;
        return cwd;
      },
      accept: async () => {
        await config.update({ responsibleUseAccepted: true });
        accepted = true;
      },
      sessions: sessionRows,
      artifacts: ({ id }) => sessionArtifacts(id),
      deleteSession: async ({ id }) => {
        requireAcceptance();
        const session = await sessions.get(sessionId(id));
        if (operator.hasSession(id))
          throw new Error("Close this session’s tab before deleting it.");
        await sessions.remove({ sessionId: id });
        try {
          await access(session.rootPath);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
          throw error;
        }
        throw new Error("Apex could not remove the session directory.");
      },
      openSessionDirectory: async ({ id }) => {
        const session = await sessions.get(sessionId(id));
        if (!Utils.openPath(session.rootPath))
          throw new Error("The session directory could not be opened.");
      },
      ...createFileRequests({
        cwd: () => cwd,
        openPath: Utils.openPath,
        requireAcceptance,
      }),
      skills: async () => {
        await skills.load({ projectRoot: cwd });
        return skills.list().map((s) => ({
          slug: s.slug,
          name: s.manifest.name,
          source: s.source,
          description: s.manifest.description,
          scripts: s.scripts.map((script) => script.name),
        }));
      },
      skillContent: async ({ slug }) =>
        (await skills.readSkillContent(slug)).content,
      quit: () => {
        setTimeout(() => Utils.quit(), 0);
      },
      openRunsCommand: async ({ command }) => {
        const [, ...args] = splitCommand(command);
        const options = parseRecordedRunsArgs(args);
        const store =
          options.databasePath && resolve(cwd, options.databasePath);
        let id = options.runId;
        if (options.specPath) {
          requireAcceptance();
          const spec = await readFile(resolve(cwd, options.specPath), "utf8");
          id = await withRuns(store, (client) => client.start(spec));
        }
        return { store, id };
      },
      runs: ({ store }) => withRuns(store, (client) => client.list()),
      watchRun: ({ id, key, store }) => {
        watching?.controller.abort();
        const controller = new AbortController();
        watching = { key, controller };
        void withRuns(store, async (client) => {
          for await (const view of client.watch(id, controller.signal)) {
            if (!controller.signal.aborted) rpc.send.runView({ key, view });
          }
        }).catch((e) => {
          if (!controller.signal.aborted)
            rpc.send.runView({ key, error: String(e) });
        });
      },
      unwatchRun: ({ key }) => {
        if (watching?.key === key) {
          watching.controller.abort();
          watching = undefined;
        }
      },
      act: async ({ id, action, store }) => {
        requireAcceptance();
        await withRuns(store, (client) => client.act(id, action));
      },
      startRun: async ({ spec, store }) => {
        requireAcceptance();
        return withRuns(store, (client) => client.start(spec));
      },
      startTerminal: ({ id, cols, rows }) => {
        requireAcceptance();
        if (child) throw new Error("A terminal is already open.");
        if (!validSize({ cols, rows }))
          throw new Error("Invalid terminal dimensions.");
        const proc = Bun.spawn(
          [process.execPath, cli, ...(id ? ["--resume", sessionId(id)] : [])],
          {
            cwd,
            env: {
              ...process.env,
              TERM: "xterm-256color",
              COLORTERM: "truecolor",
            },
            terminal: {
              cols,
              rows,
              data(_term, bytes) {
                rpc.send.output({
                  bytes: Buffer.from(bytes).toString("base64"),
                });
              },
            },
          },
        );
        child = proc;
        void proc.exited.then((code) => {
          proc.terminal?.close();
          if (child !== proc) return;
          child = undefined;
          rpc.send.exited({ code });
        });
      },
    },
    messages: {
      input: ({ data }) => child?.terminal?.write(data),
      resize: (size) => {
        if (validSize(size)) child?.terminal?.resize(size.cols, size.rows);
      },
    },
  },
});
ApplicationMenu.setApplicationMenu([
  {
    label: "Apex",
    submenu: [
      { role: "about", label: "About Apex" },
      { type: "separator" },
      { role: "hide" },
      { role: "hideOthers" },
      { role: "showAll" },
      { type: "separator" },
      { role: "quit", label: "Quit Apex" },
    ],
  },
  {
    label: "File",
    submenu: [
      { label: "New session", action: "new-session", accelerator: "n" },
      { label: "Close session", action: "close-session", accelerator: "w" },
    ],
  },
  {
    label: "Edit",
    submenu: [
      { role: "undo" },
      { role: "redo" },
      { type: "separator" },
      { role: "cut" },
      { role: "copy" },
      { role: "paste" },
      { role: "selectAll" },
    ],
  },
  {
    label: "Window",
    submenu: [
      { role: "minimize" },
      { role: "zoom" },
      { role: "toggleFullScreen" },
      { role: "bringAllToFront" },
    ],
  },
]);
ApplicationMenu.on("application-menu-clicked", (event) => {
  const { action } = (event as { data: { action: string } }).data;
  if (action === "new-session") rpc.send.sessionCommand({ type: "new" });
  if (action === "close-session") rpc.send.sessionCommand({ type: "close" });
});
const mainWindow = new BrowserWindow({
  title: "Apex",
  renderer: "cef",
  titleBarStyle: "hiddenInset",
  // Transparent CEF windows use Electrobun's low-resolution off-screen renderer.
  transparent: false,
  frame: { x: 100, y: 80, width: 1220, height: 800 },
  url,
  rpc,
  navigationRules: JSON.stringify(["^*", url]),
});
// Center the native 14px controls in the 48px app bar; reserve their width in style.css.
if (process.platform === "darwin") mainWindow.setWindowButtonPosition(12, 17);
function dispose() {
  operator.dispose();
  settings.dispose();
  watching?.controller.abort();
  const proc = child;
  child = undefined;
  proc?.kill();
  proc?.terminal?.close();
}
Electrobun.events.on("before-quit", dispose);
process.once("exit", dispose);
