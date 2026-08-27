import { useCallback, useSyncExternalStore } from "react";
import {
  accumulateSessionTokens,
  type ContextUsage,
  EMPTY_SESSION_TOKEN_USAGE,
  type SessionTokenUsage,
} from "../../core/session/usage";

// ---------------------------------------------------------------------------
// Session usage store — owns token usage per session instead of app-global
// AgentProvider state. Each session owns its cumulative totals and its latest
// root context sample; the TUI subscribes per session for live updates.
// Entering a different session switches the active view; starting another
// run in the same session never resets anything.
// ---------------------------------------------------------------------------

export interface SessionUsageState {
  tokenUsage: SessionTokenUsage;
  contextUsage: ContextUsage | null;
}

const EMPTY_STATE: SessionUsageState = {
  tokenUsage: EMPTY_SESSION_TOKEN_USAGE,
  contextUsage: null,
};

export class SessionUsageStore {
  private readonly sessions = new Map<string, SessionUsageState>();
  private readonly listeners = new Map<string, Set<() => void>>();
  private readonly activeListeners = new Set<() => void>();
  private activeId: string | null = null;

  /**
   * Tokens recorded before any session exists (a brand-new session's first
   * steps can fire before `onSessionReady` mints the session). Merged into
   * the first session entered, mirroring the old app-global accumulator.
   */
  private provisionalState: SessionUsageState = EMPTY_STATE;

  /** The session usage is currently displayed for. */
  get activeSessionId(): string | null {
    return this.activeId;
  }

  /** Start a brand-new session before it has an id. */
  beginNewSession(): void {
    const changed =
      this.activeId !== null || this.provisionalState !== EMPTY_STATE;
    this.activeId = null;
    this.provisionalState = EMPTY_STATE;
    if (changed) this.emitActive();
  }

  /**
   * Enter a session: makes it active and seeds it when not yet tracked.
   * Re-entering a tracked session (another run, a remount) keeps its
   * totals — only switching to a *different* session changes the view.
   */
  enterSession(
    sessionId: string,
    seed?: {
      tokenUsage?: SessionTokenUsage;
      contextUsage?: ContextUsage | null;
    },
  ): void {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        tokenUsage: seed?.tokenUsage ?? this.provisionalState.tokenUsage,
        contextUsage: seed?.contextUsage ?? null,
      });
      this.provisionalState = EMPTY_STATE;
    }
    if (this.activeId !== sessionId) {
      this.activeId = sessionId;
      // emit() reaches this session's listeners and — because it is now the
      // active one — the active-view listeners too.
      this.emit(sessionId);
    }
  }

  /** Drop a session's state (session deleted / left). */
  forgetSession(sessionId: string): void {
    this.sessions.delete(sessionId);
    this.listeners.delete(sessionId);
    if (this.activeId === sessionId) this.activeId = null;
  }

  /** Stable snapshot for `useSyncExternalStore`; empty until tracked. */
  getSnapshot(sessionId: string | null): SessionUsageState {
    if (sessionId === null) return EMPTY_STATE;
    return this.sessions.get(sessionId) ?? EMPTY_STATE;
  }

  subscribe(sessionId: string, listener: () => void): () => void {
    let set = this.listeners.get(sessionId);
    if (!set) {
      set = new Set();
      this.listeners.set(sessionId, set);
    }
    set.add(listener);
    return () => {
      set.delete(listener);
    };
  }

  /**
   * Accumulate one step's tokens into the owning session. A null session id
   * (session not yet created) accumulates into the provisional bucket that
   * the first entered session inherits.
   */
  addSessionTokens(
    sessionId: string | null,
    step: {
      inputTokens?: number;
      outputTokens?: number;
      cacheReadTokens?: number;
      cacheWriteTokens?: number;
    },
  ): void {
    if (sessionId === null) {
      const next = accumulateSessionTokens(
        this.provisionalState.tokenUsage,
        step,
      );
      if (next !== this.provisionalState.tokenUsage) {
        this.provisionalState = { tokenUsage: next, contextUsage: null };
        if (this.activeId === null) this.emitActive();
      }
      return;
    }
    this.update(sessionId, (state) => ({
      ...state,
      tokenUsage: accumulateSessionTokens(state.tokenUsage, step),
    }));
  }

  /**
   * Replace the latest root context sample. Subagent calls never touch it.
   * A null session id (session not yet minted) is dropped — there is no
   * owner to attach the sample to yet, and the first root step of the
   * entered session will supply a fresh one.
   */
  setRootContext(sessionId: string | null, sample: ContextUsage): void {
    if (sessionId === null) return;
    this.update(sessionId, (state) => ({
      ...state,
      contextUsage: sample,
    }));
  }

  private update(
    sessionId: string,
    updater: (state: SessionUsageState) => SessionUsageState,
  ): void {
    const current = this.sessions.get(sessionId);
    if (!current) return; // unknown session — nothing to account into
    const next = updater(current);
    if (
      next === current ||
      (next.tokenUsage === current.tokenUsage &&
        next.contextUsage === current.contextUsage)
    ) {
      return;
    }
    this.sessions.set(sessionId, next);
    this.emit(sessionId);
  }

  /** Stable snapshot of the active session or the not-yet-minted one. */
  getActiveSnapshot(): SessionUsageState {
    return this.activeId === null
      ? this.provisionalState
      : this.getSnapshot(this.activeId);
  }

  /** Subscribe to changes affecting the active-session view. */
  subscribeActive(listener: () => void): () => void {
    this.activeListeners.add(listener);
    return () => {
      this.activeListeners.delete(listener);
    };
  }

  private emit(sessionId: string): void {
    for (const listener of this.listeners.get(sessionId) ?? []) listener();
    if (sessionId === this.activeId) this.emitActive();
  }

  private emitActive(): void {
    for (const listener of this.activeListeners) listener();
  }
}

/** Subscribe to the active session's usage view (switches with the store). */
export function useActiveSessionUsage(
  store: SessionUsageStore,
): SessionUsageState {
  const subscribe = useCallback(
    (listener: () => void) => store.subscribeActive(listener),
    [store],
  );
  const getSnapshot = useCallback(() => store.getActiveSnapshot(), [store]);
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}
