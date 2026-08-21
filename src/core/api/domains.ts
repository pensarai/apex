/**
 * REST API client for workspace-scoped Pensar domains.
 *
 * API-created domains are canonicalized and created idempotently by Console.
 * They remain unverified and do not start reconnaissance.
 */

import { apiRequest } from "./apiClient";

export interface DomainSummary {
  id: string;
  url: string;
  verified: boolean;
}

export interface ListDomainsResult {
  domains: DomainSummary[];
}

export interface CreateDomainInput {
  url: string;
}

export async function listDomains(): Promise<ListDomainsResult> {
  return apiRequest<ListDomainsResult>("GET", "/domains");
}

export async function createDomain(
  data: CreateDomainInput,
): Promise<DomainSummary> {
  return apiRequest<DomainSummary>("POST", "/domains", data);
}
