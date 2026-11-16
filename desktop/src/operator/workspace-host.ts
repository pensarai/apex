import { realpath, stat } from "node:fs/promises";
import type {
  OperatorLaunch,
  OperatorMessages,
  OperatorRequests,
  OperatorTab,
} from "./contract";
import { createOperatorHost } from "./host";

type Host = ReturnType<typeof createOperatorHost>;
type Entry = {
  tabId: string;
  cwd: string;
  host: Host;
  pending: Set<Promise<unknown>>;
  initializing: boolean;
  initialization?: Promise<unknown>;
  closing: boolean;
  claimedSession?: string;
};
type Options = {
  cwd: () => string;
  requireAcceptance: () => void;
  emit: (event: OperatorMessages["operatorSnapshot"]) => void;
};
type Handlers = {
  [K in keyof OperatorRequests]: (
    params: OperatorRequests[K]["params"],
  ) =>
    | OperatorRequests[K]["response"]
    | Promise<OperatorRequests[K]["response"]>;
};

export function createOperatorWorkspace(options: Options) {
  const entries = new Map<string, Entry>();
  const opening = new Map<string, Promise<OperatorTab>>();
  let disposed = false;

  function ensureOpen() {
    options.requireAcceptance();
    if (disposed) throw new Error("The operator workspace is closed.");
  }
  function entryFor(tabId: string) {
    ensureOpen();
    const entry = entries.get(tabId);
    if (!entry) throw new Error("This session tab is no longer open.");
    if (entry.closing) throw new Error("This session tab is closing.");
    return entry;
  }
  function owner(sessionId: string) {
    return [...entries.values()].find(
      (entry) =>
        entry.host.sessionId === sessionId ||
        entry.claimedSession === sessionId,
    );
  }
  function describe(entry: Entry): OperatorTab {
    return {
      tabId: entry.tabId,
      cwd: entry.host.cwd,
      snapshot: entry.host.requests.operatorState(),
    };
  }
  function allocate() {
    ensureOpen();
    const tabId = crypto.randomUUID();
    const entry: Entry = {
      tabId,
      cwd: options.cwd(),
      host: createOperatorHost({
        cwd: () => entry.cwd,
        requireAcceptance: options.requireAcceptance,
        emit: (frame) => options.emit({ tabId, frame }),
      }),
      pending: new Set(),
      initializing: false,
      closing: false,
    };
    entries.set(tabId, entry);
    return entry;
  }
  async function track<T>(entry: Entry, operation: () => T | Promise<T>) {
    const pending = Promise.resolve().then(operation);
    entry.pending.add(pending);
    try {
      return await pending;
    } finally {
      entry.pending.delete(pending);
    }
  }
  async function initialize<T>(entry: Entry, operation: () => Promise<T>) {
    if (entry.initializing || entry.host.sessionId)
      throw new Error("Open a new tab to start or resume another session.");
    entry.initializing = true;
    const pending = track(entry, operation).finally(() => {
      entry.initializing = false;
      entry.initialization = undefined;
    });
    entry.initialization = pending;
    return pending;
  }
  async function resume(entry: Entry, id: string) {
    const existing = owner(id);
    if (existing && existing !== entry)
      throw new Error("This session is already open in another tab.");
    if (entry.host.sessionId === id) return entry.host.requests.operatorState();
    if (entry.initializing || entry.host.sessionId)
      throw new Error("Open a new tab to resume another session.");
    entry.claimedSession = id;
    try {
      return await initialize(entry, () =>
        entry.host.requests.operatorResume({ id }),
      );
    } finally {
      entry.claimedSession = undefined;
    }
  }
  function open({ sessionId }: { sessionId?: string }) {
    ensureOpen();
    if (!sessionId) return Promise.resolve(describe(allocate()));
    const pending = opening.get(sessionId);
    if (pending) return pending;
    const existing = owner(sessionId);
    if (existing) {
      entryFor(existing.tabId);
      if (existing.initializing)
        throw new Error("This session is still opening. Try again shortly.");
      return Promise.resolve(describe(existing));
    }
    const entry = allocate();
    const result = resume(entry, sessionId)
      .then(() => {
        if (disposed) throw new Error("The operator workspace is closed.");
        return describe(entry);
      })
      .catch((error) => {
        entry.host.dispose();
        entries.delete(entry.tabId);
        throw error;
      })
      .finally(() => opening.delete(sessionId));
    opening.set(sessionId, result);
    return result;
  }
  async function close({ tabId, stop }: { tabId: string; stop?: boolean }) {
    ensureOpen();
    if (!entries.has(tabId)) return;
    const entry = entryFor(tabId);
    entry.closing = true;
    try {
      // A launch may not have created its SDK client yet when the tab closes.
      await Promise.allSettled(entry.pending);
      await entry.host.close(stop);
      entries.delete(tabId);
    } finally {
      entry.closing = false;
    }
  }
  const requests = {
    operatorOpen: open,
    operatorTabs: async () => {
      ensureOpen();
      await Promise.allSettled([
        ...opening.values(),
        ...[...entries.values()].flatMap((entry) =>
          entry.initialization ? [entry.initialization] : [],
        ),
      ]);
      ensureOpen();
      return [...entries.values()]
        .filter((entry) => !entry.closing)
        .map(describe);
    },
    operatorClose: close,
    operatorSetDirectory: async ({ tabId, cwd }) => {
      const entry = entryFor(tabId);
      return track(entry, async () => {
        if (entry.initializing || entry.host.sessionId)
          throw new Error(
            "Start a new session to change its working directory.",
          );
        const directory = await realpath(cwd);
        if (!(await stat(directory)).isDirectory())
          throw new Error("Choose a working directory.");
        if (entry.initializing || entry.host.sessionId)
          throw new Error("The session started before its directory changed.");
        ensureOpen();
        entry.cwd = directory;
        return directory;
      });
    },
    operatorArguments: ({ tabId, command }) =>
      entryFor(tabId).host.requests.operatorArguments({ command }),
    operatorState: ({ tabId }) => entryFor(tabId).host.requests.operatorState(),
    operatorWatch: ({ tabId, key }) =>
      entryFor(tabId).host.requests.operatorWatch({ key }),
    operatorUnwatch: ({ tabId, key }) =>
      entries.get(tabId)?.host.requests.operatorUnwatch({ key }),
    operatorStart: ({ tabId, ...input }) => {
      const entry = entryFor(tabId);
      return initialize(entry, () => entry.host.start(input));
    },
    operatorResume: ({ tabId, id }) => resume(entryFor(tabId), id),
    operatorAction: ({ tabId, ...input }) => {
      const entry = entryFor(tabId);
      return track(entry, () => entry.host.requests.operatorAction(input));
    },
    operatorScreenshot: ({ tabId, ...input }) =>
      entryFor(tabId).host.requests.operatorScreenshot(input),
  } satisfies Handlers;

  return {
    requests,
    hasSession: (id: string) => !!owner(id),
    async start(input: OperatorLaunch) {
      const entry = allocate();
      try {
        return await initialize(entry, () => entry.host.start(input));
      } catch (error) {
        entry.host.dispose();
        entries.delete(entry.tabId);
        throw error;
      }
    },
    dispose() {
      disposed = true;
      for (const entry of entries.values()) entry.host.dispose();
      entries.clear();
    },
  };
}
