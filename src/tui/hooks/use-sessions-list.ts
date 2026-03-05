/**
 * Shared hook for loading, enriching, filtering, and grouping sessions.
 * Used by SessionsDisplay.
 */

import { useState, useEffect, useCallback } from "react";
import { existsSync, readdirSync } from "fs";
import { join } from "path";
import {
  sessions as sessionModule,
  type SessionInfo,
} from "../../core/session";
import { REPORT_FILENAME_MD } from "../../core/report";

export interface EnrichedSession extends SessionInfo {
  findingsCount: number;
  hasOperatorState: boolean;
  hasReport: boolean;
}

export interface DateGroup {
  date: string;
  timestamp: number;
  sessions: (EnrichedSession & { index: number })[];
}

function countFindings(findingsPath: string): number {
  try {
    if (!existsSync(findingsPath)) return 0;
    return readdirSync(findingsPath).filter((f) => f.endsWith(".json")).length;
  } catch {
    return 0;
  }
}

function checkHasReport(rootPath: string): boolean {
  return existsSync(join(rootPath, REPORT_FILENAME_MD));
}

export function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days === 1) return "yesterday";
  if (days < 7) return `${days}d ago`;
  return new Date(timestamp).toLocaleDateString();
}

export function useSessionsList() {
  const [allSessions, setAllSessions] = useState<EnrichedSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");

  const loadSessions = useCallback(async () => {
    setLoading(true);
    try {
      const enriched: EnrichedSession[] = [];
      for await (const session of sessionModule.list()) {
        const hasOperatorState = existsSync(
          join(session.rootPath, "messages.json"),
        );
        const findingsCount = countFindings(session.findingsPath);
        const hasReport = checkHasReport(session.rootPath);
        enriched.push({
          ...session,
          findingsCount,
          hasOperatorState,
          hasReport,
        });
      }
      // Sort by updated time (newest first)
      enriched.sort((a, b) => b.time.updated - a.time.updated);
      setAllSessions(enriched);
    } catch (error) {
      console.error("Error loading sessions:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  const deleteSession = useCallback(
    async (id: string) => {
      await sessionModule.remove({ sessionId: id });
      await loadSessions();
    },
    [loadSessions],
  );

  // Filter by search term
  const filtered = searchTerm
    ? allSessions.filter((s) =>
        s.name.toLowerCase().includes(searchTerm.toLowerCase()),
      )
    : allSessions;

  // Group by date
  const groupsMap = new Map<
    string,
    { date: string; timestamp: number; sessions: EnrichedSession[] }
  >();
  for (const session of filtered) {
    const d = new Date(session.time.created);
    const dateStr = d.toLocaleDateString("en-US", {
      weekday: "short",
      month: "short",
      day: "numeric",
      year: "numeric",
    });
    let group = groupsMap.get(dateStr);
    if (!group) {
      group = { date: dateStr, timestamp: d.getTime(), sessions: [] };
      groupsMap.set(dateStr, group);
    }
    group.sessions.push(session);
  }

  const rawGroups = Array.from(groupsMap.values());
  rawGroups.sort((a, b) => b.timestamp - a.timestamp);
  for (const g of rawGroups) {
    g.sessions.sort(
      (a, b) =>
        new Date(b.time.created).getTime() - new Date(a.time.created).getTime(),
    );
  }

  // Build visual-order flat list and indexed groups
  const visualOrderSessions: EnrichedSession[] = [];
  const groupedSessions: DateGroup[] = [];
  let idx = 0;
  for (const raw of rawGroups) {
    const group: DateGroup = {
      date: raw.date,
      timestamp: raw.timestamp,
      sessions: [],
    };
    for (const s of raw.sessions) {
      visualOrderSessions.push(s);
      group.sessions.push({ ...s, index: idx });
      idx++;
    }
    groupedSessions.push(group);
  }

  return {
    sessions: filtered,
    totalCount: filtered.length,
    groupedSessions,
    visualOrderSessions,
    loading,
    searchTerm,
    setSearchTerm,
    deleteSession,
    reload: loadSessions,
  };
}
