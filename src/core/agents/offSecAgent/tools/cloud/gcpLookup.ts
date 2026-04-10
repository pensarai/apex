import type { CloudResource, CloudLookupResult } from "./types";

interface GCPCredentials {
  projectId: string;
  serviceAccountKey: string;
}

/**
 * Get an access token from a GCP service account key.
 */
async function getAccessToken(creds: GCPCredentials): Promise<string> {
  const { GoogleAuth } = await import("google-auth-library");
  const keyData = JSON.parse(creds.serviceAccountKey);
  const auth = new GoogleAuth({
    credentials: keyData,
    scopes: ["https://www.googleapis.com/auth/cloud-platform.read-only"],
  });
  const client = await auth.getClient();
  const tokenResponse = await client.getAccessToken();
  if (!tokenResponse.token) throw new Error("Failed to obtain GCP access token");
  return tokenResponse.token;
}

async function gcpFetch(
  url: string,
  token: string,
): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GCP API ${res.status}: ${text.slice(0, 300)}`);
  }
  return (await res.json()) as Record<string, unknown>;
}

/**
 * Look up a Cloud Run service by name.
 */
async function lookupCloudRun(
  name: string,
  creds: GCPCredentials,
  region?: string,
  token?: string,
): Promise<CloudResource[]> {
  const t = token ?? (await getAccessToken(creds));
  const resources: CloudResource[] = [];

  // List all locations if no region specified, else check that region
  const regionsToCheck = region ? [region] : [];

  if (!region) {
    try {
      const locs = (await gcpFetch(
        `https://run.googleapis.com/v2/projects/${creds.projectId}/locations`,
        t,
      )) as { locations?: Array<{ locationId: string }> };
      for (const loc of locs.locations ?? []) {
        regionsToCheck.push(loc.locationId);
      }
    } catch {
      regionsToCheck.push(
        "us-central1",
        "us-east1",
        "us-west1",
        "europe-west1",
      );
    }
  }

  for (const r of regionsToCheck) {
    try {
      const svc = (await gcpFetch(
        `https://run.googleapis.com/v2/projects/${creds.projectId}/locations/${r}/services/${name}`,
        t,
      )) as {
        name?: string;
        uri?: string;
        uid?: string;
        conditions?: Array<{ type: string; state: string }>;
        ingress?: string;
      };
      const uri = svc.uri;
      resources.push({
        type: "cloud-run",
        name,
        region: r,
        url: uri,
        domain: uri ? new URL(uri).hostname : undefined,
        metadata: {
          fullName: svc.name,
          uid: svc.uid,
          ingress: svc.ingress,
        },
      });
    } catch {
      // Service not in this region
    }
  }

  return resources;
}

/**
 * Look up a Cloud Function by name.
 */
async function lookupCloudFunction(
  name: string,
  creds: GCPCredentials,
  region?: string,
  token?: string,
): Promise<CloudResource[]> {
  const t = token ?? (await getAccessToken(creds));
  const resources: CloudResource[] = [];

  const regionsToCheck = region ? [region] : [];
  if (!region) {
    regionsToCheck.push("us-central1", "us-east1", "us-west1", "europe-west1");
  }

  for (const r of regionsToCheck) {
    // Try v2 first
    try {
      const fn = (await gcpFetch(
        `https://cloudfunctions.googleapis.com/v2/projects/${creds.projectId}/locations/${r}/functions/${name}`,
        t,
      )) as {
        name?: string;
        serviceConfig?: { uri?: string };
        state?: string;
        url?: string;
      };
      const uri = fn.serviceConfig?.uri ?? fn.url;
      resources.push({
        type: "cloud-function",
        name,
        region: r,
        url: uri,
        domain: uri ? new URL(uri).hostname : undefined,
        metadata: {
          fullName: fn.name,
          state: fn.state,
        },
      });
    } catch {
      // Not in this region or v2 not available
    }

    // Try v1
    if (resources.length === 0) {
      try {
        const fn = (await gcpFetch(
          `https://cloudfunctions.googleapis.com/v1/projects/${creds.projectId}/locations/${r}/functions/${name}`,
          t,
        )) as {
          name?: string;
          httpsTrigger?: { url?: string };
          status?: string;
        };
        const uri = fn.httpsTrigger?.url;
        resources.push({
          type: "cloud-function-v1",
          name,
          region: r,
          url: uri,
          domain: uri ? new URL(uri).hostname : undefined,
          metadata: {
            fullName: fn.name,
            status: fn.status,
          },
        });
      } catch {
        // Not v1 either
      }
    }
  }

  return resources;
}

/**
 * Look up a GCS bucket.
 */
async function lookupGCSBucket(
  name: string,
  creds: GCPCredentials,
  _region?: string,
  token?: string,
): Promise<CloudResource[]> {
  const t = token ?? (await getAccessToken(creds));

  const bucket = (await gcpFetch(
    `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(name)}`,
    t,
  )) as {
    name?: string;
    location?: string;
    selfLink?: string;
    iamConfiguration?: { publicAccessPrevention?: string };
  };

  const domain = `${name}.storage.googleapis.com`;
  return [
    {
      type: "gcs-bucket",
      name: bucket.name ?? name,
      region: (bucket.location ?? "").toLowerCase(),
      url: `https://${domain}`,
      domain,
      metadata: {
        selfLink: bucket.selfLink,
        publicAccessPrevention:
          bucket.iamConfiguration?.publicAccessPrevention,
      },
    },
  ];
}

/**
 * Look up App Engine application and its default service URL.
 */
async function lookupAppEngine(
  _name: string,
  creds: GCPCredentials,
  _region?: string,
  token?: string,
): Promise<CloudResource[]> {
  const t = token ?? (await getAccessToken(creds));

  const app = (await gcpFetch(
    `https://appengine.googleapis.com/v1/apps/${creds.projectId}`,
    t,
  )) as {
    name?: string;
    defaultHostname?: string;
    locationId?: string;
    servingStatus?: string;
  };

  const domain = app.defaultHostname;
  return [
    {
      type: "app-engine",
      name: creds.projectId,
      region: app.locationId,
      url: domain ? `https://${domain}` : undefined,
      domain,
      metadata: {
        servingStatus: app.servingStatus,
      },
    },
  ];
}

/**
 * Look up a GKE cluster and its endpoint.
 */
async function lookupGKECluster(
  name: string,
  creds: GCPCredentials,
  region?: string,
  token?: string,
): Promise<CloudResource[]> {
  const t = token ?? (await getAccessToken(creds));
  const resources: CloudResource[] = [];

  // Search in specific zone/region or all
  const parent = region
    ? `projects/${creds.projectId}/locations/${region}`
    : `projects/${creds.projectId}/locations/-`;

  const resp = (await gcpFetch(
    `https://container.googleapis.com/v1/${parent}/clusters`,
    t,
  )) as { clusters?: Array<Record<string, unknown>> };

  for (const cluster of resp.clusters ?? []) {
    const clusterName = cluster.name as string | undefined;
    if (
      clusterName === name ||
      clusterName?.toLowerCase().includes(name.toLowerCase())
    ) {
      const endpoint = cluster.endpoint as string | undefined;
      resources.push({
        type: "gke-cluster",
        name: clusterName ?? name,
        region: (cluster.location as string) ?? region,
        ip: endpoint,
        url: endpoint ? `https://${endpoint}` : undefined,
        metadata: {
          status: cluster.status,
          nodeCount: cluster.currentNodeCount,
          masterVersion: cluster.currentMasterVersion,
        },
      });
    }
  }

  return resources;
}

/**
 * Look up Cloud SQL instances.
 */
async function lookupCloudSQL(
  name: string,
  creds: GCPCredentials,
  _region?: string,
  token?: string,
): Promise<CloudResource[]> {
  const t = token ?? (await getAccessToken(creds));

  const resp = (await gcpFetch(
    `https://sqladmin.googleapis.com/v1/projects/${creds.projectId}/instances/${name}`,
    t,
  )) as {
    name?: string;
    region?: string;
    ipAddresses?: Array<{ ipAddress?: string; type?: string }>;
    databaseVersion?: string;
    state?: string;
    connectionName?: string;
  };

  const publicIp = resp.ipAddresses?.find((ip) => ip.type === "PRIMARY")
    ?.ipAddress;

  return [
    {
      type: "cloud-sql",
      name: resp.name ?? name,
      region: resp.region,
      ip: publicIp,
      domain: resp.connectionName,
      metadata: {
        databaseVersion: resp.databaseVersion,
        state: resp.state,
        connectionName: resp.connectionName,
        ipAddresses: resp.ipAddresses,
      },
    },
  ];
}

/**
 * Look up a global external HTTPS load balancer by name (URL map or forwarding rule).
 */
async function lookupGCPLoadBalancer(
  name: string,
  creds: GCPCredentials,
  _region?: string,
  token?: string,
): Promise<CloudResource[]> {
  const t = token ?? (await getAccessToken(creds));
  const resources: CloudResource[] = [];

  // Check global forwarding rules
  try {
    const resp = (await gcpFetch(
      `https://compute.googleapis.com/compute/v1/projects/${creds.projectId}/global/forwardingRules`,
      t,
    )) as { items?: Array<Record<string, unknown>> };

    for (const rule of resp.items ?? []) {
      const ruleName = rule.name as string | undefined;
      if (
        ruleName === name ||
        ruleName?.toLowerCase().includes(name.toLowerCase())
      ) {
        const ipAddr = rule.IPAddress as string | undefined;
        resources.push({
          type: "gcp-load-balancer",
          name: ruleName ?? name,
          ip: ipAddr,
          url: ipAddr ? `https://${ipAddr}` : undefined,
          metadata: {
            target: rule.target,
            portRange: rule.portRange,
            loadBalancingScheme: rule.loadBalancingScheme,
          },
        });
      }
    }
  } catch {
    // No access to forwarding rules
  }

  return resources;
}

/**
 * Look up Cloud DNS records matching a domain.
 */
async function lookupCloudDNS(
  domain: string,
  creds: GCPCredentials,
  _region?: string,
  token?: string,
): Promise<CloudResource[]> {
  const t = token ?? (await getAccessToken(creds));
  const resources: CloudResource[] = [];

  const zones = (await gcpFetch(
    `https://dns.googleapis.com/dns/v1/projects/${creds.projectId}/managedZones`,
    t,
  )) as { managedZones?: Array<{ name?: string; dnsName?: string }> };

  for (const zone of zones.managedZones ?? []) {
    const zoneDns = zone.dnsName?.replace(/\.$/, "") ?? "";
    if (!domain.endsWith(zoneDns) && domain !== zoneDns) continue;

    const records = (await gcpFetch(
      `https://dns.googleapis.com/dns/v1/projects/${creds.projectId}/managedZones/${zone.name}/rrsets`,
      t,
    )) as { rrsets?: Array<Record<string, unknown>> };

    for (const rr of records.rrsets ?? []) {
      const rrName = ((rr.name as string) ?? "").replace(/\.$/, "");
      if (
        rrName === domain ||
        rrName.endsWith(`.${domain}`) ||
        domain.endsWith(`.${rrName}`)
      ) {
        const rrdatas = (rr.rrdatas ?? []) as string[];
        resources.push({
          type: "cloud-dns-record",
          name: rrName,
          domain: rrdatas[0] ?? rrName,
          metadata: {
            type: rr.type,
            ttl: rr.ttl,
            rrdatas,
            zone: zone.name,
          },
        });
      }
    }
  }

  return resources;
}

const SERVICE_LOOKUP: Record<
  string,
  (
    id: string,
    creds: GCPCredentials,
    region?: string,
    token?: string,
  ) => Promise<CloudResource[]>
> = {
  cloudrun: lookupCloudRun,
  cloudfunction: lookupCloudFunction,
  gcs: lookupGCSBucket,
  appengine: lookupAppEngine,
  gke: lookupGKECluster,
  cloudsql: lookupCloudSQL,
  loadbalancer: lookupGCPLoadBalancer,
  clouddns: lookupCloudDNS,
};

export async function gcpLookup(
  resourceType: string,
  identifier: string,
  creds: GCPCredentials,
  region?: string,
): Promise<CloudLookupResult> {
  const key = resourceType.toLowerCase().replace(/[-_ ]/g, "");
  const lookupFn = SERVICE_LOOKUP[key];

  if (!lookupFn) {
    return {
      success: false,
      provider: "gcp",
      resources: [],
      error: `Unsupported GCP resource type: ${resourceType}. Supported types: ${Object.keys(SERVICE_LOOKUP).join(", ")}`,
    };
  }

  try {
    const token = await getAccessToken(creds);
    const resources = await lookupFn(identifier, creds, region, token);
    return { success: true, provider: "gcp", resources };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      provider: "gcp",
      resources: [],
      error: `GCP lookup failed for ${resourceType}/${identifier}: ${msg}`,
    };
  }
}
