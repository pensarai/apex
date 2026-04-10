import type { CloudResource, CloudLookupResult } from "./types";

interface AWSCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

async function fetchJSON(
  url: string,
  init: RequestInit,
): Promise<Record<string, unknown>> {
  const res = await fetch(url, init);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`AWS API ${res.status}: ${text.slice(0, 200)}`);
  }
  return (await res.json()) as Record<string, unknown>;
}

/**
 * Look up a Lambda function's URL/ARN by name.
 */
async function lookupLambda(
  name: string,
  creds: AWSCredentials,
  region?: string,
): Promise<CloudResource[]> {
  const { LambdaClient, GetFunctionCommand, GetFunctionUrlConfigCommand } =
    await import("@aws-sdk/client-lambda");
  const client = new LambdaClient({
    region: region ?? creds.region,
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
    },
  });

  const fn = await client.send(new GetFunctionCommand({ FunctionName: name }));
  const arn = fn.Configuration?.FunctionArn ?? "";

  let functionUrl: string | undefined;
  try {
    const urlConfig = await client.send(
      new GetFunctionUrlConfigCommand({ FunctionName: name }),
    );
    functionUrl = urlConfig.FunctionUrl ?? undefined;
  } catch {
    // Function URL not configured — not an error
  }

  const domain = functionUrl
    ? new URL(functionUrl).hostname
    : undefined;

  return [
    {
      type: "lambda",
      name: fn.Configuration?.FunctionName ?? name,
      region: region ?? creds.region,
      arn,
      url: functionUrl,
      domain,
      metadata: {
        runtime: fn.Configuration?.Runtime,
        handler: fn.Configuration?.Handler,
        memorySize: fn.Configuration?.MemorySize,
        timeout: fn.Configuration?.Timeout,
        lastModified: fn.Configuration?.LastModified,
      },
    },
  ];
}

/**
 * Resolve an S3 bucket's website/regional endpoint.
 */
async function lookupS3Bucket(
  name: string,
  creds: AWSCredentials,
): Promise<CloudResource[]> {
  const { S3Client, GetBucketLocationCommand, GetBucketWebsiteCommand } =
    await import("@aws-sdk/client-s3");
  const client = new S3Client({
    region: creds.region,
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
    },
  });

  let bucketRegion = creds.region;
  try {
    const loc = await client.send(
      new GetBucketLocationCommand({ Bucket: name }),
    );
    if (loc.LocationConstraint) {
      bucketRegion = loc.LocationConstraint;
    }
  } catch {
    // Use default region
  }

  let isWebsite = false;
  try {
    await client.send(new GetBucketWebsiteCommand({ Bucket: name }));
    isWebsite = true;
  } catch {
    // No website config
  }

  const regionalDomain = `${name}.s3.${bucketRegion}.amazonaws.com`;
  const websiteDomain = isWebsite
    ? `${name}.s3-website-${bucketRegion}.amazonaws.com`
    : undefined;

  return [
    {
      type: "s3-bucket",
      name,
      region: bucketRegion,
      arn: `arn:aws:s3:::${name}`,
      url: `https://${regionalDomain}`,
      domain: websiteDomain ?? regionalDomain,
      metadata: { isWebsite, websiteDomain },
    },
  ];
}

/**
 * Look up a CloudFront distribution by ID or domain alias.
 */
async function lookupCloudFront(
  identifier: string,
  creds: AWSCredentials,
): Promise<CloudResource[]> {
  const { CloudFrontClient, ListDistributionsCommand } = await import(
    // @ts-expect-error dynamic import
    "@aws-sdk/client-cloudfront"
  );
  const client = new CloudFrontClient({
    region: "us-east-1",
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
    },
  });

  const list = await client.send(new ListDistributionsCommand({}));
  const items = list.DistributionList?.Items ?? [];

  const matches = items.filter((d: any) => {
    if (d.Id === identifier) return true;
    const aliases = d.Aliases?.Items ?? [];
    return aliases.some(
      (a: any) =>
        a === identifier ||
        a.endsWith(`.${identifier}`) ||
        identifier.endsWith(`.${a}`),
    );
  });

  return matches.map((d: any) => ({
    type: "cloudfront-distribution",
    name: d.Id ?? identifier,
    domain: d.DomainName ?? undefined,
    url: d.DomainName ? `https://${d.DomainName}` : undefined,
    arn: d.ARN ?? undefined,
    metadata: {
      aliases: d.Aliases?.Items ?? [],
      origins: (d.Origins?.Items ?? []).map((o: any) => ({
        id: o.Id,
        domainName: o.DomainName,
      })),
      enabled: d.Enabled,
      status: d.Status,
    },
  }));
}

/**
 * Look up an API Gateway REST or HTTP API by name or ID.
 */
async function lookupAPIGateway(
  identifier: string,
  creds: AWSCredentials,
  region?: string,
): Promise<CloudResource[]> {
  const resources: CloudResource[] = [];
  const r = region ?? creds.region;

  // REST APIs (v1)
  try {
    const { APIGatewayClient, GetRestApisCommand } = await import(
      // @ts-expect-error dynamic import
      "@aws-sdk/client-api-gateway"
    );
    const client = new APIGatewayClient({
      region: r,
      credentials: {
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
      },
    });
    const apis = await client.send(new GetRestApisCommand({}));
    for (const api of apis.items ?? []) {
      if (
        api.id === identifier ||
        api.name?.toLowerCase().includes(identifier.toLowerCase())
      ) {
        const domain = `${api.id}.execute-api.${r}.amazonaws.com`;
        resources.push({
          type: "apigateway-rest",
          name: api.name ?? api.id ?? identifier,
          region: r,
          url: `https://${domain}`,
          domain,
          metadata: {
            apiId: api.id,
            description: api.description,
            createdDate: api.createdDate?.toISOString(),
          },
        });
      }
    }
  } catch {
    // REST API access may not be available
  }

  // HTTP APIs (v2)
  try {
    const { ApiGatewayV2Client, GetApisCommand } = await import(
      // @ts-expect-error dynamic import
      "@aws-sdk/client-apigatewayv2"
    );
    const client = new ApiGatewayV2Client({
      region: r,
      credentials: {
        accessKeyId: creds.accessKeyId,
        secretAccessKey: creds.secretAccessKey,
      },
    });
    const apis = await client.send(new GetApisCommand({}));
    for (const api of apis.Items ?? []) {
      if (
        api.ApiId === identifier ||
        api.Name?.toLowerCase().includes(identifier.toLowerCase())
      ) {
        const domain = api.ApiEndpoint
          ? new URL(api.ApiEndpoint).hostname
          : `${api.ApiId}.execute-api.${r}.amazonaws.com`;
        resources.push({
          type: "apigateway-http",
          name: api.Name ?? api.ApiId ?? identifier,
          region: r,
          url: api.ApiEndpoint ?? `https://${domain}`,
          domain,
          metadata: {
            apiId: api.ApiId,
            protocol: api.ProtocolType,
            description: api.Description,
          },
        });
      }
    }
  } catch {
    // HTTP API access may not be available
  }

  return resources;
}

/**
 * Look up an ELB/ALB/NLB by name.
 */
async function lookupLoadBalancer(
  name: string,
  creds: AWSCredentials,
  region?: string,
): Promise<CloudResource[]> {
  const {
    ElasticLoadBalancingV2Client,
    DescribeLoadBalancersCommand,
  } = await import(
    // @ts-expect-error dynamic import
    "@aws-sdk/client-elastic-load-balancing-v2"
  );
  const client = new ElasticLoadBalancingV2Client({
    region: region ?? creds.region,
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
    },
  });

  const resp = await client.send(new DescribeLoadBalancersCommand({}));
  const matches = (resp.LoadBalancers ?? []).filter(
    (lb: any) =>
      lb.LoadBalancerName === name ||
      lb.LoadBalancerName?.toLowerCase().includes(name.toLowerCase()) ||
      lb.LoadBalancerArn?.includes(name),
  );

  return matches.map((lb: any) => ({
    type: `elb-${lb.Type ?? "unknown"}`,
    name: lb.LoadBalancerName ?? name,
    region: region ?? creds.region,
    arn: lb.LoadBalancerArn,
    domain: lb.DNSName ?? undefined,
    url: lb.DNSName ? `https://${lb.DNSName}` : undefined,
    metadata: {
      scheme: lb.Scheme,
      type: lb.Type,
      state: lb.State?.Code,
      vpcId: lb.VpcId,
      availabilityZones: lb.AvailabilityZones?.map((az: any) => az.ZoneName),
    },
  }));
}

/**
 * Look up an ECS service to get its associated load balancer / public IP.
 */
async function lookupECSService(
  identifier: string,
  creds: AWSCredentials,
  region?: string,
): Promise<CloudResource[]> {
  const {
    ECSClient,
    ListClustersCommand,
    ListServicesCommand,
    DescribeServicesCommand,
  } = await import("@aws-sdk/client-ecs");
  const r = region ?? creds.region;
  const client = new ECSClient({
    region: r,
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
    },
  });

  const resources: CloudResource[] = [];
  const clusters = await client.send(new ListClustersCommand({}));

  for (const clusterArn of clusters.clusterArns ?? []) {
    try {
      const services = await client.send(
        new ListServicesCommand({ cluster: clusterArn }),
      );
      const matching = (services.serviceArns ?? []).filter(
        (arn) =>
          arn.includes(identifier) ||
          arn.split("/").pop()?.toLowerCase().includes(identifier.toLowerCase()),
      );
      if (matching.length === 0) continue;

      const desc = await client.send(
        new DescribeServicesCommand({
          cluster: clusterArn,
          services: matching,
        }),
      );

      for (const svc of desc.services ?? []) {
        const lbs = svc.loadBalancers ?? [];
        resources.push({
          type: "ecs-service",
          name: svc.serviceName ?? identifier,
          region: r,
          arn: svc.serviceArn,
          metadata: {
            cluster: clusterArn.split("/").pop(),
            desiredCount: svc.desiredCount,
            runningCount: svc.runningCount,
            launchType: svc.launchType,
            loadBalancers: lbs.map((lb) => ({
              targetGroupArn: lb.targetGroupArn,
              containerName: lb.containerName,
              containerPort: lb.containerPort,
            })),
          },
        });
      }
    } catch {
      // May not have access to this cluster
    }
  }

  return resources;
}

/**
 * Look up an RDS instance by identifier.
 */
async function lookupRDS(
  identifier: string,
  creds: AWSCredentials,
  region?: string,
): Promise<CloudResource[]> {
  const { RDSClient, DescribeDBInstancesCommand } = await import(
    "@aws-sdk/client-rds"
  );
  const client = new RDSClient({
    region: region ?? creds.region,
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
    },
  });

  try {
    const resp = await client.send(
      new DescribeDBInstancesCommand({
        DBInstanceIdentifier: identifier,
      }),
    );
    return (resp.DBInstances ?? []).map((db) => ({
      type: "rds",
      name: db.DBInstanceIdentifier ?? identifier,
      region: region ?? creds.region,
      arn: db.DBInstanceArn,
      domain: db.Endpoint?.Address ?? undefined,
      url: db.Endpoint
        ? `${db.Endpoint.Address}:${db.Endpoint.Port}`
        : undefined,
      metadata: {
        engine: db.Engine,
        engineVersion: db.EngineVersion,
        port: db.Endpoint?.Port,
        publiclyAccessible: db.PubliclyAccessible,
        vpcId: db.DBSubnetGroup?.VpcId,
      },
    }));
  } catch {
    // Instance not found or no access
    return [];
  }
}

/**
 * Look up Route 53 hosted zones and records matching a domain.
 */
async function lookupRoute53(
  domain: string,
  creds: AWSCredentials,
): Promise<CloudResource[]> {
  const {
    Route53Client,
    ListHostedZonesCommand,
    ListResourceRecordSetsCommand,
  } = await import(
    // @ts-expect-error dynamic import
    "@aws-sdk/client-route-53"
  );
  const client = new Route53Client({
    region: "us-east-1",
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
    },
  });

  const resources: CloudResource[] = [];
  const zones = await client.send(new ListHostedZonesCommand({}));

  for (const zone of zones.HostedZones ?? []) {
    const zoneName = zone.Name?.replace(/\.$/, "") ?? "";
    if (
      !domain.endsWith(zoneName) &&
      domain !== zoneName &&
      !zoneName.endsWith(domain)
    ) {
      continue;
    }

    const records = await client.send(
      new ListResourceRecordSetsCommand({ HostedZoneId: zone.Id! }),
    );

    for (const rr of records.ResourceRecordSets ?? []) {
      const recordName = rr.Name?.replace(/\.$/, "") ?? "";
      if (
        recordName === domain ||
        recordName.endsWith(`.${domain}`) ||
        domain.endsWith(`.${recordName}`)
      ) {
        const values =
          rr.ResourceRecords?.map((r: any) => r.Value ?? "").filter(Boolean) ?? [];
        const alias = rr.AliasTarget?.DNSName?.replace(/\.$/, "");

        resources.push({
          type: "route53-record",
          name: recordName,
          domain: alias ?? (values.length > 0 ? values[0] : recordName),
          metadata: {
            type: rr.Type,
            ttl: rr.TTL,
            values,
            aliasTarget: alias,
            hostedZone: zoneName,
          },
        });
      }
    }
  }

  return resources;
}

/**
 * Look up EC2 instances by name tag, instance ID, or IP.
 */
async function lookupEC2(
  identifier: string,
  creds: AWSCredentials,
  region?: string,
): Promise<CloudResource[]> {
  const { EC2Client, DescribeInstancesCommand } = await import(
    "@aws-sdk/client-ec2"
  );
  const r = region ?? creds.region;
  const client = new EC2Client({
    region: r,
    credentials: {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
    },
  });

  const isInstanceId = identifier.startsWith("i-");
  const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(identifier);

  const filters = isInstanceId
    ? [{ Name: "instance-id" as const, Values: [identifier] }]
    : isIP
      ? [{ Name: "ip-address" as const, Values: [identifier] }]
      : [{ Name: "tag:Name" as const, Values: [`*${identifier}*`] }];

  const resp = await client.send(
    new DescribeInstancesCommand({ Filters: filters }),
  );

  const resources: CloudResource[] = [];
  for (const reservation of resp.Reservations ?? []) {
    for (const inst of reservation.Instances ?? []) {
      const nameTag = inst.Tags?.find((t) => t.Key === "Name")?.Value;
      resources.push({
        type: "ec2",
        name: nameTag ?? inst.InstanceId ?? identifier,
        region: r,
        ip: inst.PublicIpAddress ?? undefined,
        domain: inst.PublicDnsName ?? undefined,
        url: inst.PublicDnsName
          ? `http://${inst.PublicDnsName}`
          : inst.PublicIpAddress
            ? `http://${inst.PublicIpAddress}`
            : undefined,
        metadata: {
          instanceId: inst.InstanceId,
          instanceType: inst.InstanceType,
          state: inst.State?.Name,
          privateIp: inst.PrivateIpAddress,
          privateDns: inst.PrivateDnsName,
          vpcId: inst.VpcId,
          subnetId: inst.SubnetId,
          securityGroups: inst.SecurityGroups?.map((sg) => ({
            id: sg.GroupId,
            name: sg.GroupName,
          })),
        },
      });
    }
  }

  return resources;
}

const SERVICE_LOOKUP: Record<
  string,
  (
    id: string,
    creds: AWSCredentials,
    region?: string,
  ) => Promise<CloudResource[]>
> = {
  lambda: lookupLambda,
  s3: lookupS3Bucket,
  cloudfront: lookupCloudFront,
  apigateway: lookupAPIGateway,
  elb: lookupLoadBalancer,
  alb: lookupLoadBalancer,
  nlb: lookupLoadBalancer,
  ecs: lookupECSService,
  rds: lookupRDS,
  route53: lookupRoute53,
  ec2: lookupEC2,
};

export async function awsLookup(
  resourceType: string,
  identifier: string,
  creds: AWSCredentials,
  region?: string,
): Promise<CloudLookupResult> {
  const key = resourceType.toLowerCase().replace(/[-_ ]/g, "");
  const lookupFn = SERVICE_LOOKUP[key];

  if (!lookupFn) {
    return {
      success: false,
      provider: "aws",
      resources: [],
      error: `Unsupported AWS resource type: ${resourceType}. Supported types: ${Object.keys(SERVICE_LOOKUP).join(", ")}`,
    };
  }

  try {
    const resources = await lookupFn(identifier, creds, region);
    return { success: true, provider: "aws", resources };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      provider: "aws",
      resources: [],
      error: `AWS lookup failed for ${resourceType}/${identifier}: ${msg}`,
    };
  }
}
