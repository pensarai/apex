import { apiRequest } from "./apiClient";
import type { SiemTriageResult } from "./siemTriage";

export interface IncidentSummary {
  id: string;
  url: string;
  provider: "datadog";
  externalId: string;
  title: string;
  ruleName: string | null;
  sourceSeverity: string | null;
  sourceUrl: string | null;
  occurredAt: string;
  lastSeenAt: string;
  occurrenceCount: number;
  status: "open" | "resolved" | "dismissed";
  triageStatus: "pending" | "running" | "completed" | "failed";
  verdict: SiemTriageResult["verdict"] | null;
  confidence: SiemTriageResult["confidence"] | null;
  assessedSeverity: SiemTriageResult["severity"] | null;
  triageSummary: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  workspaceId: string;
  integrationId: string | null;
  message: string | null;
  tags: string[];
  entities: {
    ips: string[];
    hosts: string[];
    users: string[];
    services: string[];
    urls: string[];
  };
  rawPayload: Record<string, unknown>;
  triageResult: SiemTriageResult | null;
  triageError: string | null;
  sessionId: string | null;
  triageStartedAt: string | null;
  triageCompletedAt: string | null;
  resolvedAt: string | null;
  resolvedBy: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface IncidentListOptions {
  limit?: number;
  cursor?: string;
  verdict?: NonNullable<IncidentSummary["verdict"]>;
  status?: IncidentSummary["status"];
  triageStatus?: IncidentSummary["triageStatus"];
}

export interface IncidentPage {
  incidents: Array<
    IncidentSummary & { eventCount: number; firstOccurredAt: string }
  >;
  nextCursor: string | null;
}

export interface IncidentEventPage {
  events: IncidentSummary[];
  nextCursor: string | null;
}

export interface IncidentLogPage {
  sessionId: string | null;
  parts: Array<{
    id: string;
    sessionId: string;
    messageId: string;
    sequence: number;
    index: number;
    role: "user" | "assistant" | "system";
    messageData: Record<string, unknown> | null;
    stepSeq: number | null;
    type: string;
    toolCallId: string | null;
    data: Record<string, unknown> | null;
    hasAttachment: boolean;
    createdAt: string;
    updatedAt: string;
  }>;
  nextCursor: string | null;
}

function queryString(options: object): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(options)) {
    if (value !== undefined) query.set(key, String(value));
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

export function listIncidents(
  options: IncidentListOptions = {},
): Promise<IncidentPage> {
  return apiRequest("GET", `/incidents${queryString(options)}`);
}

export function listIncidentEvents(
  options: IncidentListOptions & { groupOf?: string } = {},
): Promise<IncidentEventPage> {
  return apiRequest("GET", `/incidents/events${queryString(options)}`);
}

export function getIncident(incidentId: string): Promise<IncidentDetail> {
  return apiRequest("GET", `/incidents/${encodeURIComponent(incidentId)}`);
}

export function listIncidentLogs(
  incidentId: string,
  options: Pick<IncidentListOptions, "limit" | "cursor"> = {},
): Promise<IncidentLogPage> {
  return apiRequest(
    "GET",
    `/incidents/${encodeURIComponent(incidentId)}/logs${queryString(options)}`,
  );
}

export function getIncidentLogAttachment(
  incidentId: string,
  partId: string,
): Promise<{ downloadUrl: string; expiresIn: number }> {
  return apiRequest(
    "GET",
    `/incidents/${encodeURIComponent(incidentId)}/logs/${encodeURIComponent(partId)}/attachment`,
  );
}
