import { readFile } from "node:fs/promises";
import path from "node:path";
import { throwIfReconAborted } from "./abort";
import { normalizeRepositoryPath } from "./identity";
import { CONFIG_NETWORK_PATTERNS, CONFIG_RESOURCE_PATTERNS } from "./selectors";
import type {
  ConfigOwnershipRule,
  ReconApplication,
  ReconResource,
  ReconSurface,
  RepositoryInventory,
  ResourceType,
  UnresolvedItem,
} from "./types";

export interface DomainObservation {
  application_id: string;
  domain: string;
  source_file: string;
  source_line: number;
}

export interface ConfigArtifactResult {
  surfaces: ReconSurface[];
  resources: ReconResource[];
  domains: DomainObservation[];
  unresolved: UnresolvedItem[];
  handled_files: string[];
}

interface Assignment {
  key: string;
  value: string;
}

export async function extractConfigArtifacts(
  inventory: RepositoryInventory,
  applications: ReconApplication[],
  ownershipRules: ConfigOwnershipRule[] = [],
  abortSignal?: AbortSignal,
): Promise<ConfigArtifactResult> {
  const surfaces: ReconSurface[] = [];
  const resources: ReconResource[] = [];
  const domains: DomainObservation[] = [];
  const unresolved: UnresolvedItem[] = [];
  const handledFiles: string[] = [];

  for (const file of inventory.files) {
    throwIfReconAborted(abortSignal);
    if (file.relevance !== "analyze" || file.kind !== "config") continue;
    const absolutePath = path.join(
      inventory.repository_root,
      ...file.path.split("/"),
    );
    let content: string;
    try {
      content = await readFile(absolutePath, "utf8");
    } catch (error) {
      unresolved.push({
        kind: "inventory",
        summary: `Could not read configuration artifact ${file.path}`,
        source_files: [file.path],
        reason: error instanceof Error ? error.message : String(error),
      });
      continue;
    }
    const lines = content.split("\n");
    const signalLines = lines.flatMap((line, index) => {
      const network = CONFIG_NETWORK_PATTERNS.some((pattern) =>
        pattern.test(line),
      );
      const resource = CONFIG_RESOURCE_PATTERNS.some((pattern) =>
        pattern.test(line),
      );
      return network || resource ? [{ index, line, network, resource }] : [];
    });
    if (signalLines.length === 0) continue;

    const applicationId = applicationForPath(
      file.path,
      applications,
      ownershipRules,
    );
    if (!applicationId) {
      unresolved.push({
        kind: "application-assignment",
        summary: `Configuration identities in ${file.path} have no unique application`,
        source_files: [file.path],
        reason: `config-artifact-application-ambiguous:${signalLines.length}-signals`,
      });
      handledFiles.push(file.path);
      continue;
    }

    const nonliteralLines: number[] = [];
    for (const signal of signalLines) {
      const assignment = parseAssignment(signal.line);
      const lineNumber = signal.index + 1;
      if (!assignment) {
        const uri = safeConnectionUri(signal.line);
        if (uri && signal.resource) {
          resources.push(
            resourceObservation(
              applicationId,
              inferResourceType("", uri),
              inferProvider("", uri),
              uri,
              file.path,
              lineNumber,
            ),
          );
        } else {
          nonliteralLines.push(lineNumber);
        }
        continue;
      }
      const value = literalValue(assignment.value);
      if (!value) {
        if (!isStructuralValue(assignment.value)) {
          nonliteralLines.push(lineNumber);
        }
        continue;
      }

      const resourceType = inferResourceType(assignment.key, value);
      if (resourceType) {
        const identifier = identifierWithNearbyPort(value, lines, signal.index);
        if (!identifier) {
          nonliteralLines.push(lineNumber);
          continue;
        }
        resources.push(
          resourceObservation(
            applicationId,
            resourceType,
            inferProvider(assignment.key, value),
            identifier,
            file.path,
            lineNumber,
          ),
        );
        continue;
      }

      const key = assignment.key.toUpperCase();
      if (isPortKey(key) && /^\d{1,5}$/.test(value)) {
        if (nearbyResourceIdentifier(lines, signal.index)) continue;
        surfaces.push({
          application_id: applicationId,
          type: "network",
          method: "CONFIG",
          path_or_name: `port:${value}`,
          source_file: file.path,
          source_line: lineNumber,
        });
        continue;
      }

      const identifier = safeNetworkIdentifier(value);
      if (!identifier) {
        nonliteralLines.push(lineNumber);
        continue;
      }
      if (isApplicationIdentityKey(key)) {
        surfaces.push({
          application_id: applicationId,
          type: "network",
          method: "CONFIG",
          path_or_name: identifier,
          source_file: file.path,
          source_line: lineNumber,
        });
        const domain = publicDomain(identifier);
        if (domain) {
          domains.push({
            application_id: applicationId,
            domain,
            source_file: file.path,
            source_line: lineNumber,
          });
        }
      } else {
        resources.push(
          resourceObservation(
            applicationId,
            "service",
            "configured-service",
            identifier,
            file.path,
            lineNumber,
          ),
        );
      }
    }

    if (nonliteralLines.length > 0) {
      const visible = nonliteralLines.slice(0, 20).join(",");
      unresolved.push({
        kind: "resource",
        summary: `Non-literal configuration identities in ${file.path}`,
        source_files: [file.path],
        reason: `nonliteral-config-lines:${visible}${nonliteralLines.length > 20 ? `;and-${nonliteralLines.length - 20}-more` : ""}`,
      });
    }
    handledFiles.push(file.path);
  }

  return {
    surfaces: deduplicate(surfaces),
    resources: deduplicate(resources),
    domains: deduplicate(domains),
    unresolved,
    handled_files: [...new Set(handledFiles)].sort(),
  };
}

function parseAssignment(line: string): Assignment | null {
  const match = line.match(
    /^\s*(?:-\s*)?["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*(.*?)\s*[,;]?\s*$/,
  );
  return match?.[1] && match[2] !== undefined
    ? { key: match[1], value: match[2] }
    : null;
}

function literalValue(rawValue: string): string | null {
  let value = rawValue.trim().replace(/[,;]\s*$/, "");
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1).trim();
  }
  if (
    !value ||
    value === "[REDACTED]" ||
    /^(?:null|undefined|true|false|string|number|boolean)$/i.test(value) ||
    value.startsWith("${") ||
    value.startsWith("{{") ||
    value.includes("$$(")
  ) {
    return null;
  }
  return value;
}

function isStructuralValue(rawValue: string): boolean {
  const value = rawValue.trim();
  return (
    value === "" ||
    value.startsWith("{") ||
    value.startsWith("[") ||
    /^(?:string|number|boolean|null|undefined)$/i.test(value)
  );
}

function inferResourceType(key: string, value: string): ResourceType | null {
  const signal = `${key} ${value}`.toLowerCase();
  if (/bucket|\bs3\b|storage\.googleapis/.test(signal)) return "bucket";
  if (/redis|memcached|elasticache|memorydb|cache_url/.test(signal)) {
    return "cache";
  }
  if (
    /kafka|confluent|rabbitmq|\bamqp\b|\bsqs\b|\bsns\b|\bnats\b|broker/.test(
      signal,
    )
  ) {
    return "queue";
  }
  if (
    /database|\bdb_|postgres|pgbouncer|pg-proxy|mysql|mariadb|mongo|dynamo|cockroach|elasticsearch|opensearch|\.rds\.amazonaws\.com|\.es\.amazonaws\.com/.test(
      signal,
    )
  ) {
    return "database";
  }
  return null;
}

function inferProvider(key: string, value: string): string {
  const signal = `${key} ${value}`.toLowerCase();
  if (/\.rds\.amazonaws\.com|\brds\b/.test(signal)) return "AWS RDS";
  if (/elasticache/.test(signal)) return "AWS ElastiCache";
  if (/memorydb/.test(signal)) return "AWS MemoryDB";
  if (/\.es\.amazonaws\.com|opensearch|elasticsearch/.test(signal)) {
    return "AWS OpenSearch";
  }
  if (/dynamodb|dynamo/.test(signal)) return "AWS DynamoDB";
  if (/\bs3\b|bucket/.test(signal)) return "AWS S3";
  if (/\bsqs\b/.test(signal)) return "AWS SQS";
  if (/\bsns\b/.test(signal)) return "AWS SNS";
  if (/postgres|pgbouncer|pg-proxy/.test(signal)) return "PostgreSQL";
  if (/mysql|mariadb/.test(signal)) return "MySQL";
  if (/mongo/.test(signal)) return "MongoDB";
  if (/redis/.test(signal)) return "Redis";
  if (/confluent/.test(signal)) return "Confluent Kafka";
  if (/kafka/.test(signal)) return "Kafka";
  if (/rabbitmq|amqp/.test(signal)) return "RabbitMQ";
  if (/nats/.test(signal)) return "NATS";
  return "configured-resource";
}

function resourceObservation(
  applicationId: string,
  type: ResourceType | null,
  provider: string,
  identifier: string,
  sourceFile: string,
  sourceLine: number,
): ReconResource {
  return {
    application_id: applicationId,
    type: type ?? "service",
    provider,
    identifier,
    source_file: sourceFile,
    source_line: sourceLine,
  };
}

function identifierWithNearbyPort(
  value: string,
  lines: string[],
  index: number,
): string | null {
  const identifier = safeNetworkIdentifier(value);
  if (!identifier) return null;
  if (/:[0-9]{1,5}(?:\/|$)/.test(identifier)) return identifier;
  for (let offset = 1; offset <= 5; offset++) {
    for (const candidateIndex of [index - offset, index + offset]) {
      const line = lines[candidateIndex];
      if (line === undefined) continue;
      const assignment = parseAssignment(line);
      const port = assignment ? literalValue(assignment.value) : null;
      if (
        assignment &&
        isPortKey(assignment.key.toUpperCase()) &&
        port &&
        /^\d{1,5}$/.test(port)
      ) {
        return `${identifier}:${port}`;
      }
    }
  }
  return identifier;
}

function nearbyResourceIdentifier(lines: string[], index: number): boolean {
  for (let offset = 1; offset <= 5; offset++) {
    for (const candidateIndex of [index - offset, index + offset]) {
      const line = lines[candidateIndex];
      if (line === undefined) continue;
      const assignment = parseAssignment(line);
      const value = assignment ? literalValue(assignment.value) : null;
      if (
        assignment &&
        value &&
        (inferResourceType(assignment.key, value) ||
          /^(?:host|hostname)$/i.test(assignment.key))
      ) {
        return true;
      }
    }
  }
  return false;
}

function safeNetworkIdentifier(value: string): string | null {
  const connection = safeConnectionUri(value);
  if (connection) return connection;
  const candidate = value.trim().replace(/^['"]|['"]$/g, "");
  if (
    !candidate ||
    candidate.includes("${") ||
    candidate.includes("{{") ||
    /\s/.test(candidate) ||
    candidate.startsWith(".") ||
    candidate.startsWith("/") ||
    /^(?:file|secret|vault|vscode):\/\//i.test(candidate)
  ) {
    return null;
  }
  return candidate;
}

function safeConnectionUri(value: string): string | null {
  const match = value.match(
    /\b(https?|postgres(?:ql)?|mysql|mongodb|redis|amqp|nats):\/\/[^\s"']+/i,
  );
  if (!match?.[0]) return null;
  try {
    const url = new URL(match[0].replace(/[,;)]$/, ""));
    const pathName = url.pathname === "/" ? "" : url.pathname;
    return `${url.protocol}//${url.host}${pathName}`;
  } catch {
    return null;
  }
}

function isPortKey(key: string): boolean {
  return key === "PORT" || key.endsWith("_PORT");
}

function isApplicationIdentityKey(key: string): boolean {
  return (
    key === "DOMAIN" ||
    key === "PUBLIC_URL" ||
    key.endsWith("_DOMAIN") ||
    key.endsWith("_PUBLIC_URL")
  );
}

function publicDomain(identifier: string): string | null {
  let host = identifier;
  try {
    host = new URL(identifier).hostname;
  } catch {
    host = identifier.replace(/:\d+$/, "");
  }
  if (
    !host.includes(".") ||
    /^(?:localhost|\d{1,3}(?:\.\d{1,3}){3})$/.test(host) ||
    /\.(?:internal|local|localhost)$/.test(host)
  ) {
    return null;
  }
  return host.toLowerCase();
}

function applicationForPath(
  filePath: string,
  applications: ReconApplication[],
  ownershipRules: ConfigOwnershipRule[],
): string | null {
  const ownershipMatches = ownershipRules
    .flatMap((rule) => {
      const prefix =
        rule.path_prefix === "."
          ? "."
          : normalizeRepositoryPath(rule.path_prefix);
      return prefix && isWithinRoot(filePath, prefix)
        ? [{ applicationId: rule.application_id, prefix }]
        : [];
    })
    .sort((a, b) => b.prefix.length - a.prefix.length);
  const longestPrefix = ownershipMatches[0]?.prefix.length;
  const ownedApplicationIds = [
    ...new Set(
      ownershipMatches
        .filter((match) => match.prefix.length === longestPrefix)
        .map((match) => match.applicationId)
        .filter((id) =>
          applications.some((application) => application.id === id),
        ),
    ),
  ];
  if (ownedApplicationIds.length === 1) return ownedApplicationIds[0] ?? null;

  const matches = applications.flatMap((application) =>
    application.source_roots.flatMap((root) => {
      const normalized = root === "." ? "." : normalizeRepositoryPath(root);
      return normalized && isWithinRoot(filePath, normalized)
        ? [{ applicationId: application.id, root: normalized }]
        : [];
    }),
  );
  matches.sort((a, b) => b.root.length - a.root.length);
  const longest = matches[0]?.root.length;
  const applicationIds = [
    ...new Set(
      matches
        .filter((match) => match.root.length === longest)
        .map((match) => match.applicationId),
    ),
  ];
  if (applicationIds.length === 1) return applicationIds[0] ?? null;
  return applications.length === 1 ? (applications[0]?.id ?? null) : null;
}

function isWithinRoot(filePath: string, root: string): boolean {
  return root === "." || filePath === root || filePath.startsWith(`${root}/`);
}

function deduplicate<T>(values: T[]): T[] {
  return [
    ...new Map(values.map((value) => [JSON.stringify(value), value])).values(),
  ];
}
