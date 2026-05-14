/**
 * REST API client for the Pensar attack surface (apps & endpoints).
 *
 * Wraps the apps/endpoints routes on the console's issues-api Lambda
 * (`/{proxy+}` API Gateway).
 *
 * Endpoint surface:
 *   GET    /projects/:projectId/apps
 *   POST   /projects/:projectId/apps
 *   GET    /apps/:appId
 *   PATCH  /apps/:appId
 *   DELETE /apps/:appId
 *   GET    /apps/:appId/endpoints
 *   POST   /apps/:appId/endpoints
 *   GET    /endpoints/:endpointId
 *   PATCH  /endpoints/:endpointId
 *   DELETE /endpoints/:endpointId
 */

import { apiRequest } from "./apiClient";

// ── Enums ────────────────────────────────────────────────────────────

export type ApplicationType =
  | "ui"
  | "api-service"
  | "web-application"
  | "full-stack"
  | "domain"
  | "subdomain"
  | "database"
  | "cloud-resource"
  | "storage";

export type EndpointType =
  | "api-endpoint"
  | "web-endpoint"
  | "auth-endpoint"
  | "database"
  | "file-storage"
  | "asset";

// ── Types ────────────────────────────────────────────────────────────

export interface AppSummary {
  id: string;
  name: string;
  type: string | null;
  framework: string | null;
  projectId: string;
  domainId: string | null;
  createdAt: string;
}

export interface AppDetail extends AppSummary {
  description: string;
  disallowedActions: string | null;
}

export interface EndpointSummary {
  id: string;
  endpoint: string;
  type: string | null;
  applicationId: string;
  location: string | null;
  riskScore: number | null;
  objectives: string[];
  createdAt: string;
}

export interface EndpointDetail extends EndpointSummary {
  description: string;
  startLineNumber: number | null;
  endLineNumber: number | null;
  authenticationRequired: {
    required: boolean;
    details: string | null;
  } | null;
  riskScoreBreakdown: {
    score: number;
    explanation: string;
    breakdown: {
      exposure: number;
      dataSensitivity: number;
      functionCriticality: number;
      securityIndicators: number;
    };
  } | null;
  businessLogic: string | null;
  threatModel: string | null;
}

export interface ListEndpointsPage {
  endpoints: EndpointSummary[];
  hasMore: boolean;
  limit: number;
  offset: number;
}

export interface CreateAppInput {
  name: string;
  description: string;
  type?: ApplicationType;
  framework?: string;
  domainId?: string;
  disallowedActions?: string;
}

export interface UpdateAppInput {
  name?: string;
  description?: string;
  type?: ApplicationType | null;
  framework?: string | null;
  domainId?: string | null;
  disallowedActions?: string | null;
}

export interface CreateEndpointInput {
  endpoint: string;
  description: string;
  type?: EndpointType;
  location?: string;
  startLineNumber?: number;
  endLineNumber?: number;
  objectives?: string[];
  authenticationRequired?: {
    required: boolean;
    details?: string | null;
  };
  businessLogic?: string;
  threatModel?: string;
}

export interface UpdateEndpointInput {
  endpoint?: string;
  description?: string;
  type?: EndpointType | null;
  location?: string | null;
  startLineNumber?: number | null;
  endLineNumber?: number | null;
  objectives?: string[];
  authenticationRequired?: {
    required: boolean;
    details?: string | null;
  } | null;
  businessLogic?: string | null;
  threatModel?: string | null;
}

export interface DeleteResult {
  success: boolean;
  appId?: string;
  endpointId?: string;
}

// ── Apps ─────────────────────────────────────────────────────────────

export async function listApps(projectId: string): Promise<AppSummary[]> {
  return apiRequest<AppSummary[]>("GET", `/projects/${projectId}/apps`);
}

export async function getApp(appId: string): Promise<AppDetail> {
  return apiRequest<AppDetail>("GET", `/apps/${appId}`);
}

export async function createApp(
  projectId: string,
  data: CreateAppInput,
): Promise<AppDetail> {
  return apiRequest<AppDetail>("POST", `/projects/${projectId}/apps`, data);
}

export async function updateApp(
  appId: string,
  data: UpdateAppInput,
): Promise<AppDetail> {
  return apiRequest<AppDetail>("PATCH", `/apps/${appId}`, data);
}

export async function deleteApp(appId: string): Promise<DeleteResult> {
  return apiRequest<DeleteResult>("DELETE", `/apps/${appId}`);
}

// ── Endpoints ────────────────────────────────────────────────────────

export interface ListEndpointsFilters {
  type?: EndpointType;
  minRiskScore?: number;
  limit?: number;
  offset?: number;
}

export async function listEndpoints(
  appId: string,
  filters?: ListEndpointsFilters,
): Promise<EndpointSummary[] | ListEndpointsPage> {
  const params = new URLSearchParams();
  if (filters?.type) params.set("type", filters.type);
  if (filters?.minRiskScore !== undefined) {
    params.set("minRiskScore", String(filters.minRiskScore));
  }
  if (filters?.limit !== undefined) params.set("limit", String(filters.limit));
  if (filters?.offset !== undefined) {
    params.set("offset", String(filters.offset));
  }

  const qs = params.toString();
  const path = `/apps/${appId}/endpoints${qs ? `?${qs}` : ""}`;
  return apiRequest<EndpointSummary[] | ListEndpointsPage>("GET", path);
}

export async function getEndpoint(endpointId: string): Promise<EndpointDetail> {
  return apiRequest<EndpointDetail>("GET", `/endpoints/${endpointId}`);
}

export async function createEndpoint(
  appId: string,
  data: CreateEndpointInput,
): Promise<EndpointDetail> {
  return apiRequest<EndpointDetail>("POST", `/apps/${appId}/endpoints`, data);
}

export async function updateEndpoint(
  endpointId: string,
  data: UpdateEndpointInput,
): Promise<EndpointDetail> {
  return apiRequest<EndpointDetail>("PATCH", `/endpoints/${endpointId}`, data);
}

export async function deleteEndpoint(
  endpointId: string,
): Promise<DeleteResult> {
  return apiRequest<DeleteResult>("DELETE", `/endpoints/${endpointId}`);
}
