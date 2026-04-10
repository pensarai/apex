export interface CloudResource {
  type: string;
  name: string;
  region?: string;
  arn?: string;
  url?: string;
  domain?: string;
  ip?: string;
  metadata?: Record<string, unknown>;
}

export interface CloudLookupResult {
  success: boolean;
  provider: string;
  resources: CloudResource[];
  error?: string;
}
