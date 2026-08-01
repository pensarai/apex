import { readFile } from "node:fs/promises";
import path from "node:path";
import { throwIfReconAborted } from "./abort";
import { normalizeStringSet, shortHash } from "./identity";
import type {
  CandidateLedger,
  FileScan,
  InventoryFile,
  LiteralSelector,
  ReconCandidate,
  ReconSelector,
  RepositoryInventory,
  SelectorCategory,
  UnresolvedItem,
} from "./types";

interface BuiltinMatcher {
  selector: ReconSelector;
  patterns: RegExp[];
  pathPattern?: RegExp;
  requiredPathPattern?: RegExp;
  fileKinds?: Set<InventoryFile["kind"]>;
}

interface SelectorMatch {
  selectorId: string;
  category: SelectorCategory;
  line: number;
}

interface CandidateDraft {
  selectorIds: string[];
  categories: SelectorCategory[];
  lineStart: number;
  lineEnd: number;
  snippet: string;
  signature: string;
  truncated: boolean;
}

export interface SelectorScanOptions {
  maxCandidates?: number;
  snippetContextLines?: number;
  maxSnippetCharacters?: number;
  suppressedBuiltinSelectors?: ReadonlyMap<string, ReadonlySet<string>>;
  abortSignal?: AbortSignal;
}

const DEFAULT_MAX_CANDIDATES = 20_000;
const DEFAULT_CONTEXT_LINES = 3;
const DEFAULT_MAX_SNIPPET_CHARACTERS = 6_000;

export const CONFIG_NETWORK_SELECTOR_ID = "builtin-network-config-key";
export const CONFIG_RESOURCE_SELECTOR_ID = "builtin-resource-config-key";
export const CONFIG_NETWORK_PATTERNS = [
  /^\s*["']?(?:(?:HOST|HOSTNAME|DOMAIN|ORIGIN|ENDPOINT|PORT|PUBLIC_URL|BASE_URL|API_URL)|[A-Z0-9_]+_(?:HOST|HOSTNAME|DOMAIN|ORIGIN|ENDPOINT|PORT|PUBLIC_URL|BASE_URL|API_URL))["']?\s*[:=]/,
  /^\s*["']?(?:host|hostname|domain|origin|endpoint|port|publicUrl|baseUrl|apiUrl|url)["']?\s*:\s*["']?(?:https?:\/\/|[A-Za-z0-9.-]+(?::\d+)?)/i,
];
export const CONFIG_RESOURCE_PATTERNS = [
  /^\s*["']?(?:DATABASE_URL|DB_(?:HOST|PORT|NAME|URL)|POSTGRES_(?:HOST|PORT|DB|DATABASE|URL)|MYSQL_(?:HOST|PORT|DATABASE|URL)|MONGO(?:DB)?_(?:HOST|PORT|DATABASE|URL)|REDIS_(?:HOST|PORT|URL)|CACHE_URL|QUEUE_URL|BROKER_URL|KAFKA_BROKERS?|RABBITMQ_URL|SQS_(?:URL|QUEUE|ARN)|SNS_(?:TOPIC|ARN)|[A-Z0-9_]*BUCKET(?:_NAME|_ARN|_URL)?)["']?\s*[:=]/,
  /^\s*["']?(?:database|postgres|mysql|mongodb|redis|broker|kafka|rabbitmq|sqs|sns|bucket)["']?\s*:/i,
  /\b(?:postgres(?:ql)?|mysql|mongodb|redis|amqp|nats):\/\//i,
];

const BUILTIN_MATCHERS: BuiltinMatcher[] = [
  matcher(
    "builtin-application-manifest",
    "application",
    "Package or build target with a deployable server signal",
    [
      /"(?:start|serve)"\s*:/i,
      /"(?:express|fastify|next|nestjs|hono|koa|@apollo\/server)"\s*:/i,
      /\b(?:uvicorn|gunicorn|flask|fastapi|django|spring-boot|rails\s+server)\b/i,
    ],
    undefined,
    ["manifest", "build"],
  ),
  matcher(
    "builtin-application-container",
    "application",
    "Container deployment boundary",
    [/^\s*(?:ENTRYPOINT|CMD|FROM)\b/i, /^\s*services\s*:/i],
    /(?:^|\/)(?:Dockerfile(?:\..+)?|compose\.ya?ml)$/i,
    ["container"],
  ),
  matcher(
    "builtin-application-deployment",
    "application",
    "Infrastructure deployment boundary",
    [
      /^\s*kind:\s*(?:Deployment|StatefulSet|DaemonSet|Service|Ingress)\b/i,
      /^\s*(?:resource|module)\s+["'](?:aws_(?:ecs_service|lambda_function|apprunner_service)|google_cloud_run_service|azurerm_(?:linux|windows)_web_app|kubernetes_(?:deployment|stateful_set|service|ingress))\b/i,
      /\bnew\s+(?:aws\.(?:ecs\.Service|lambda\.Function)|k8s\.apps\.v1\.Deployment|gcp\.cloudrun\.Service)\s*\(/,
    ],
    /(?:^|\/)(?:serverless\.ya?ml|Chart\.ya?ml)$/i,
    ["infrastructure"],
  ),
  matcher(
    "builtin-application-entrypoint",
    "application",
    "Language application entrypoint",
    [
      /\b(?:func\s+main|static\s+void\s+main|if\s+__name__\s*==\s*["']__main__["'])\b/,
    ],
    undefined,
    ["source"],
    /(?:^|\/)(?:main|server|app|manage)\.[^.]+$/i,
  ),
  matcher(
    "builtin-http-registration",
    "http",
    "HTTP route, controller, middleware mount, or file-system route registration",
    [
      /\b(?:app|router|server|api|route|fastify)\s*\.\s*(?:get|post|put|patch|delete|options|head|all|use|route)\s*\(/i,
      /@(?:Get|Post|Put|Patch|Delete|Options|Head|RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\b/,
      /@\w+\.(?:get|post|put|patch|delete|options|head|route|api_route)\s*\(/i,
      /\b(?:http\.)?(?:Handle|HandleFunc)\s*\(/,
      /\b(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*\(\s*["'`/]/,
      /\b(?:path|re_path|url)\s*\(\s*["']/,
      /\b(?:resources?|namespace|scope|mount)\s+(?:[:"'])/,
      /\b(?:Route|MapGet|MapPost|MapPut|MapPatch|MapDelete)\s*\(/,
    ],
    /(?:^|\/)(?:app\/.*\/route|pages\/api\/.*|routes?)\.(?:[cm]?[jt]sx?|py|rb|go|php)$/i,
    ["source", "config", "api-spec"],
  ),
  matcher(
    "builtin-graphql-registration",
    "graphql",
    "GraphQL schema field, resolver map, or operation registration",
    [
      /^\s*(?:extend\s+)?type\s+(?:Query|Mutation|Subscription)\b/,
      /^\s*(?:Query|Mutation|Subscription)\s*:\s*\{/,
      /\b(?:buildSchema|makeExecutableSchema|createSchema)\s*\(/,
      /\b(?:resolvers|typeDefs)\s*[:=]/,
      /@(?:Query|Mutation|Subscription|Resolver)\b/,
    ],
    undefined,
    ["source"],
  ),
  matcher(
    "builtin-grpc-registration",
    "grpc",
    "gRPC service, RPC declaration, server registration, or implementation",
    [
      /^\s*(?:service|rpc)\s+[A-Za-z_][A-Za-z0-9_]*/,
      /\b(?:addService|registerService|Register.*Server|bindService)\s*\(/,
      /\b(?:grpc\.|ServerInterceptor|Servicer)\b/,
    ],
    undefined,
    ["source", "config"],
  ),
  matcher(
    "builtin-network-listener",
    "network",
    "Application listener registration",
    [/\.\s*listen\s*\(/i, /\b(?:server|socket)\s*\.\s*bind\s*\(/i],
    undefined,
    ["source"],
  ),
  matcher(
    "builtin-network-infrastructure",
    "network",
    "Infrastructure host, port, ingress, load balancer, or DNS exposure",
    [
      /^\s*(?:containerPort|hostPort|nodePort|targetPort|port)\s*:/,
      /^\s*(?:host|hostname|hosts)\s*:/i,
      /\b(?:Ingress|LoadBalancer|aws_lb|aws_route53|cloudflare_record|google_compute_forwarding_rule)\b/,
      /\b(?:url|uri|domain|hostname|endpoint|origin)\s*[:=]\s*["']?https?:\/\//i,
    ],
    undefined,
    ["container", "infrastructure"],
  ),
  matcher(
    "builtin-network-proxy-config",
    "network",
    "Reverse-proxy host, port, or upstream exposure",
    [
      /\b(?:listen|server_name|proxy_pass|upstream)\b/i,
      /\bhttps?:\/\/[A-Za-z0-9.-]+(?::\d+)?/,
    ],
    undefined,
    ["config"],
    /(?:nginx|caddy|traefik|haproxy|ingress|proxy|gateway)/i,
  ),
  matcher(
    CONFIG_NETWORK_SELECTOR_ID,
    "network",
    "Explicit host, domain, URL, endpoint, or port configuration",
    CONFIG_NETWORK_PATTERNS,
    undefined,
    ["config"],
  ),
  matcher(
    "builtin-resource-manifest",
    "resource",
    "Database, cache, queue, or cloud-storage client dependency",
    [
      /^\s*["']?(?:pg|postgres|postgresql|mysql2?|mariadb|mongodb|mongoose|redis|ioredis|memcached|kafkajs|amqplib|nats|boto3|@aws-sdk\/client-(?:s3|sqs|sns|dynamodb))["']?\s*[:=]/i,
      /^\s*(?:psycopg\d*|asyncpg|pymongo|redis|sqlalchemy|celery|boto3)(?:\W|$)/i,
      /<artifactId>(?:postgresql|mysql-connector-j|mongodb-driver-sync|jedis|lettuce-core|kafka-clients|amqp-client)<\/artifactId>/i,
    ],
    undefined,
    ["manifest", "build"],
  ),
  matcher(
    "builtin-resource-infrastructure",
    "resource",
    "Infrastructure database, cache, queue, bucket, or upstream service",
    [
      /\b(?:aws_(?:db_instance|rds_cluster|elasticache_cluster|dynamodb_table|s3_bucket|sqs_queue|sns_topic)|google_(?:sql_database_instance|redis_instance|storage_bucket|pubsub_topic)|azurerm_(?:postgresql|mysql|redis|storage|servicebus)[A-Za-z0-9_]*)\b/i,
      /\bnew\s+(?:aws\.(?:rds\.(?:Instance|Cluster)|elasticache\.(?:Cluster|ReplicationGroup)|dynamodb\.Table|s3\.Bucket|sqs\.Queue|sns\.Topic)|gcp\.(?:sql|redis|storage|pubsub)\.[A-Za-z0-9_.]+)\b/,
      /\b(?:engine|image|service|type)\s*[:=]\s*["']?(?:postgres(?:ql)?|mysql|mariadb|mongodb|dynamodb|cockroachdb|redis|memcached|elasticache|kafka|rabbitmq|sqs|sns|pubsub|nats)\b/i,
      /^\s*(?:postgres(?:ql)?|mysql|mariadb|mongodb|dynamodb|redis|kafka|rabbitmq|nats)\s*:\s*$/i,
      /\bsource\s*=\s*["'][^"']*(?:rds|redis|kafka|rabbitmq|s3|sqs|sns)[^"']*["']/i,
      /\b(?:DATABASE_URL|REDIS_URL|QUEUE_URL|BROKER_URL)\b/,
      /\b(?:postgres(?:ql)?|mysql|mongodb|redis|amqp|nats):\/\//i,
    ],
    undefined,
    ["container", "infrastructure"],
  ),
  matcher(
    CONFIG_RESOURCE_SELECTOR_ID,
    "resource",
    "Explicit database, cache, queue, bucket, or broker configuration",
    CONFIG_RESOURCE_PATTERNS,
    undefined,
    ["config"],
  ),
];

export function builtInSelectors(): ReconSelector[] {
  return BUILTIN_MATCHERS.map(({ selector }) => selector);
}

export async function scanRepositoryForCandidates(
  inventory: RepositoryInventory,
  plannerSelectors: LiteralSelector[] = [],
  options: SelectorScanOptions = {},
): Promise<CandidateLedger> {
  const maxCandidates = options.maxCandidates ?? DEFAULT_MAX_CANDIDATES;
  const contextLines = options.snippetContextLines ?? DEFAULT_CONTEXT_LINES;
  const maxSnippetCharacters = Math.max(
    512,
    options.maxSnippetCharacters ?? DEFAULT_MAX_SNIPPET_CHARACTERS,
  );
  const selectors = [
    ...builtInSelectors(),
    ...plannerSelectors.map<ReconSelector>((literal) => ({
      id: `planner-${shortHash(JSON.stringify(literal), 14)}`,
      category: literal.category,
      description: literal.description,
      source: "planner",
      kind: "literal",
      literal,
    })),
  ];
  const candidates = new Map<string, ReconCandidate>();
  const inventoryPaths = new Set(inventory.files.map((file) => file.path));
  const files: FileScan[] = [];
  const errors: UnresolvedItem[] = [];
  let capReported = false;

  for (const file of inventory.files) {
    throwIfReconAborted(options.abortSignal);
    if (file.relevance !== "analyze") continue;
    const absolutePath = path.join(
      inventory.repository_root,
      ...file.path.split("/"),
    );
    let content: string;
    try {
      content = await readFile(absolutePath, "utf8");
    } catch (error) {
      files.push({
        path: file.path,
        status: "unresolved",
        candidate_ids: [],
        reason: `selector-read-failed:${errorMessage(error)}`,
      });
      continue;
    }

    const lines = content.split("\n");
    const dependencyContext = resolveRelativeDependencies(
      file.path,
      lines,
      inventoryPaths,
    );
    const matches = collectMatches(
      file,
      content,
      lines,
      plannerSelectors,
      options.suppressedBuiltinSelectors?.get(file.path),
    );
    const drafts = buildCandidateDrafts(
      file,
      lines,
      matches,
      contextLines,
      maxSnippetCharacters,
    );
    const candidateIds: string[] = [];
    let fileIncomplete = false;
    if (drafts.some((draft) => draft.truncated)) {
      fileIncomplete = true;
      errors.push({
        kind: "selector",
        summary: `Evidence line exceeded the candidate size limit in ${file.path}`,
        source_files: [file.path],
        reason: `candidate-evidence-line-exceeds-${maxSnippetCharacters}-characters`,
      });
    }
    for (const draft of drafts) {
      if (candidates.size >= maxCandidates) {
        fileIncomplete = true;
        if (!capReported) {
          errors.push({
            kind: "budget",
            summary: "Candidate safety limit reached",
            source_files: [file.path],
            reason: `candidate-count-exceeds-${maxCandidates}`,
          });
          capReported = true;
        }
        continue;
      }
      const identity = `${file.path}:${draft.signature}`;
      const id = `candidate-${shortHash(identity, 18)}`;
      const current = candidates.get(id);
      if (current) {
        current.selector_ids = normalizeStringSet([
          ...current.selector_ids,
          ...draft.selectorIds,
        ]);
        current.categories = normalizeStringSet([
          ...current.categories,
          ...draft.categories,
        ]) as SelectorCategory[];
      } else {
        candidates.set(id, {
          id,
          selector_ids: draft.selectorIds,
          categories: draft.categories,
          path: file.path,
          line_start: draft.lineStart,
          line_end: draft.lineEnd,
          snippet: draft.snippet,
          dependency_context: dependencyContext,
        });
      }
      candidateIds.push(id);
    }

    files.push({
      path: file.path,
      status:
        fileIncomplete || drafts.length > candidateIds.length
          ? "unresolved"
          : candidateIds.length > 0
            ? "candidate"
            : "no-signal",
      candidate_ids: normalizeStringSet(candidateIds),
      reason: drafts.some((draft) => draft.truncated)
        ? "candidate-evidence-truncated"
        : drafts.length > candidateIds.length
          ? "candidate-safety-limit-reached"
          : undefined,
    });
  }

  const candidatePaths = new Set(
    [...candidates.values()].map((candidate) => candidate.path),
  );
  const candidateValues = [...candidates.values()]
    .map((candidate) => ({
      ...candidate,
      dependency_context: candidate.dependency_context.filter((dependency) =>
        candidatePaths.has(dependency.resolved_path),
      ),
    }))
    .sort(compareCandidates);

  return {
    selectors,
    candidates: candidateValues,
    files: files.sort((a, b) => a.path.localeCompare(b.path)),
    errors,
  };
}

export function buildPlannerContext(
  inventory: RepositoryInventory,
  seedLedger: CandidateLedger,
  maxCharacters = 96_000,
): string {
  const byLanguage = countBy(
    inventory.files.filter((file) => file.language),
    (file) => file.language ?? "unknown",
  );
  const byKind = countBy(inventory.files, (file) => file.kind);
  const byTopLevel = countBy(inventory.files, (file) => topLevel(file.path));
  const selectorMatches = Object.fromEntries(
    seedLedger.selectors.map((selector) => [
      selector.id,
      seedLedger.candidates.filter((candidate) =>
        candidate.selector_ids.includes(selector.id),
      ).length,
    ]),
  );
  const representativeCandidates = selectRepresentativeCandidates(
    seedLedger.candidates,
    80,
  ).map((candidate) => ({
    id: candidate.id,
    categories: candidate.categories,
    path: candidate.path,
    lines: `${candidate.line_start}-${candidate.line_end}`,
    snippet: candidate.snippet,
    dependencies: candidate.dependency_context,
  }));
  const highSignalPaths = stratifiedPaths(
    inventory.files.filter((file) => file.high_signal),
    240,
  );
  const allConfigurationSignalPaths = normalizeStringSet(
    seedLedger.candidates
      .filter((candidate) =>
        candidate.selector_ids.some((selectorId) =>
          [CONFIG_NETWORK_SELECTOR_ID, CONFIG_RESOURCE_SELECTOR_ID].includes(
            selectorId,
          ),
        ),
      )
      .map((candidate) => candidate.path),
  );
  const configurationSignalPaths = allConfigurationSignalPaths.slice(0, 500);
  const context = JSON.stringify(
    {
      repository_root: inventory.repository_root,
      totals: {
        files: inventory.files.length,
        analyzable: inventory.files.filter(
          (file) => file.relevance === "analyze",
        ).length,
        excluded_directories: inventory.excluded_directories.length,
      },
      files_by_language: byLanguage,
      files_by_kind: byKind,
      files_by_top_level: byTopLevel,
      high_signal_paths: highSignalPaths,
      high_signal_paths_omitted: Math.max(
        0,
        inventory.files.filter((file) => file.high_signal).length -
          highSignalPaths.length,
      ),
      configuration_signal_paths: configurationSignalPaths,
      configuration_signal_paths_omitted: Math.max(
        0,
        allConfigurationSignalPaths.length - configurationSignalPaths.length,
      ),
      builtin_selector_matches: selectorMatches,
      representative_evidence: representativeCandidates,
    },
    null,
    2,
  );
  return truncateMiddle(context, maxCharacters);
}

function matcher(
  id: string,
  category: SelectorCategory,
  description: string,
  patterns: RegExp[],
  pathPattern?: RegExp,
  fileKinds?: InventoryFile["kind"][],
  requiredPathPattern?: RegExp,
): BuiltinMatcher {
  return {
    selector: {
      id,
      category,
      description,
      source: "builtin",
      kind: "builtin",
    },
    patterns,
    pathPattern,
    requiredPathPattern,
    fileKinds: fileKinds ? new Set(fileKinds) : undefined,
  };
}

function collectMatches(
  file: InventoryFile,
  content: string,
  lines: string[],
  plannerSelectors: LiteralSelector[],
  suppressedBuiltinSelectors?: ReadonlySet<string>,
): SelectorMatch[] {
  const matches: SelectorMatch[] = [];
  if (file.kind !== "test" && file.kind !== "documentation") {
    for (const builtin of BUILTIN_MATCHERS) {
      if (suppressedBuiltinSelectors?.has(builtin.selector.id)) continue;
      if (builtin.fileKinds && !builtin.fileKinds.has(file.kind)) continue;
      if (
        builtin.requiredPathPattern &&
        !builtin.requiredPathPattern.test(file.path)
      ) {
        continue;
      }
      if (builtin.pathPattern?.test(file.path)) {
        matches.push({
          selectorId: builtin.selector.id,
          category: builtin.selector.category,
          line: 1,
        });
      }
      lines.forEach((line, index) => {
        if (builtin.patterns.some((pattern) => pattern.test(line))) {
          matches.push({
            selectorId: builtin.selector.id,
            category: builtin.selector.category,
            line: index + 1,
          });
        }
      });
    }
  }

  for (const selector of plannerSelectors) {
    if (!literalSelectorApplies(selector, file, content)) continue;
    const normalizedLiterals = selector.literals.map((literal) =>
      selector.case_sensitive ? literal : literal.toLowerCase(),
    );
    lines.forEach((line, index) => {
      const haystack = selector.case_sensitive ? line : line.toLowerCase();
      const tests = normalizedLiterals.map((literal) =>
        haystack.includes(literal),
      );
      const matched =
        selector.match === "all" ? tests.every(Boolean) : tests.some(Boolean);
      if (matched) {
        matches.push({
          selectorId: `planner-${shortHash(JSON.stringify(selector), 14)}`,
          category: selector.category,
          line: index + 1,
        });
      }
    });
  }

  const deduplicated = new Map<string, (typeof matches)[number]>();
  for (const match of matches) {
    deduplicated.set(
      `${match.selectorId}:${match.category}:${match.line}`,
      match,
    );
  }
  return [...deduplicated.values()].sort(
    (a, b) => a.line - b.line || a.selectorId.localeCompare(b.selectorId),
  );
}

function buildCandidateDrafts(
  file: InventoryFile,
  lines: string[],
  matches: SelectorMatch[],
  contextLines: number,
  maxCharacters: number,
): CandidateDraft[] {
  const matchesByLine = new Map<
    number,
    {
      line: number;
      selectorIds: string[];
      categories: SelectorCategory[];
      contextLines: number;
    }
  >();
  for (const match of matches) {
    const existing = matchesByLine.get(match.line) ?? {
      line: match.line,
      selectorIds: [],
      categories: [],
      contextLines: evidenceContextLines(file, match, contextLines),
    };
    existing.selectorIds = normalizeStringSet([
      ...existing.selectorIds,
      match.selectorId,
    ]);
    existing.categories = normalizeStringSet([
      ...existing.categories,
      match.category,
    ]) as SelectorCategory[];
    existing.contextLines = Math.max(
      existing.contextLines,
      evidenceContextLines(file, match, contextLines),
    );
    matchesByLine.set(match.line, existing);
  }
  const lineMatches = [...matchesByLine.values()].sort(
    (a, b) => a.line - b.line,
  );
  const fragments: CandidateDraft[] = [];
  let group: typeof lineMatches = [];

  const flushGroup = () => {
    if (group.length === 0) return;
    fragments.push(createEvidenceFragment(lines, group, maxCharacters));
    group = [];
  };

  for (const match of lineMatches) {
    const proposed = [...group, match];
    const fragment = createEvidenceFragment(
      lines,
      proposed,
      Number.POSITIVE_INFINITY,
    );
    if (group.length > 0 && fragment.snippet.length > maxCharacters) {
      flushGroup();
    }
    group.push(match);
  }
  flushGroup();

  const drafts: CandidateDraft[] = [];
  let packed: CandidateDraft[] = [];
  const flushPacked = () => {
    if (packed.length === 0) return;
    const separator = "\n       |... non-matching lines omitted ...\n";
    drafts.push({
      selectorIds: normalizeStringSet(
        packed.flatMap((fragment) => fragment.selectorIds),
      ),
      categories: normalizeStringSet(
        packed.flatMap((fragment) => fragment.categories),
      ) as SelectorCategory[],
      lineStart: Math.min(...packed.map((fragment) => fragment.lineStart)),
      lineEnd: Math.max(...packed.map((fragment) => fragment.lineEnd)),
      snippet: packed.map((fragment) => fragment.snippet).join(separator),
      signature: packed.map((fragment) => fragment.signature).join(";"),
      truncated: packed.some((fragment) => fragment.truncated),
    });
    packed = [];
  };
  for (const fragment of fragments) {
    const proposedLength =
      packed.reduce((total, item) => total + item.snippet.length, 0) +
      fragment.snippet.length +
      packed.length * 48;
    if (packed.length > 0 && proposedLength > maxCharacters) flushPacked();
    packed.push(fragment);
  }
  flushPacked();
  return drafts;
}

function createEvidenceFragment(
  lines: string[],
  matches: Array<{
    line: number;
    selectorIds: string[];
    categories: SelectorCategory[];
    contextLines: number;
  }>,
  maxCharacters: number,
): CandidateDraft {
  const lineStart = Math.max(
    1,
    Math.min(...matches.map((match) => match.line - match.contextLines)),
  );
  const lineEnd = Math.min(
    lines.length,
    Math.max(...matches.map((match) => match.line + match.contextLines)),
  );
  const snippet = formatSnippet(lines, lineStart, lineEnd);
  const truncated = snippet.length > maxCharacters;
  return {
    selectorIds: normalizeStringSet(
      matches.flatMap((match) => match.selectorIds),
    ),
    categories: normalizeStringSet(
      matches.flatMap((match) => match.categories),
    ) as SelectorCategory[],
    lineStart,
    lineEnd,
    snippet: truncated ? truncateMiddle(snippet, maxCharacters) : snippet,
    signature: matches
      .map((match) => `${match.line}:${match.selectorIds.join("+")}`)
      .join(","),
    truncated,
  };
}

function evidenceContextLines(
  file: InventoryFile,
  match: SelectorMatch,
  defaultContextLines: number,
): number {
  if (
    file.kind === "source" ||
    ["http", "graphql", "grpc"].includes(match.category)
  ) {
    return defaultContextLines;
  }
  if (file.kind === "container" || file.kind === "infrastructure") {
    return Math.min(defaultContextLines, 1);
  }
  return 0;
}

function literalSelectorApplies(
  selector: LiteralSelector,
  file: InventoryFile,
  content: string,
): boolean {
  if (file.kind === "test" || file.kind === "documentation") return false;
  if (
    selector.extensions.length > 0 &&
    !selector.extensions.some((extension) =>
      file.path
        .toLowerCase()
        .endsWith(
          extension.startsWith(".")
            ? extension.toLowerCase()
            : `.${extension.toLowerCase()}`,
        ),
    )
  ) {
    return false;
  }
  if (
    selector.path_contains.length > 0 &&
    !selector.path_contains.some((part) =>
      file.path.toLowerCase().includes(part.toLowerCase()),
    )
  ) {
    return false;
  }
  if (selector.match !== "all") return true;
  const haystack = selector.case_sensitive ? content : content.toLowerCase();
  return selector.literals.every((literal) =>
    haystack.includes(
      selector.case_sensitive ? literal : literal.toLowerCase(),
    ),
  );
}

function resolveRelativeDependencies(
  filePath: string,
  lines: string[],
  inventoryPaths: ReadonlySet<string>,
): ReconCandidate["dependency_context"] {
  const dependencies: ReconCandidate["dependency_context"] = [];
  lines.forEach((line, index) => {
    const specifiers = [
      ...line.matchAll(
        /(?:\bfrom\s*|\brequire\s*\(|\bimport\s*\()["'](\.{1,2}\/[^"']+)["']/g,
      ),
    ];
    for (const match of specifiers) {
      const specifier = match[1];
      if (!specifier) continue;
      const resolvedPath = resolveImportPath(
        filePath,
        specifier,
        inventoryPaths,
      );
      if (!resolvedPath) continue;
      dependencies.push({
        source_line: index + 1,
        statement: redactPossibleSecret(line.trim()),
        resolved_path: resolvedPath,
      });
    }
  });
  return [
    ...new Map(
      dependencies.map((dependency) => [
        `${dependency.source_line}:${dependency.resolved_path}`,
        dependency,
      ]),
    ).values(),
  ].sort(
    (a, b) =>
      a.source_line - b.source_line ||
      a.resolved_path.localeCompare(b.resolved_path),
  );
}

function resolveImportPath(
  filePath: string,
  specifier: string,
  inventoryPaths: ReadonlySet<string>,
): string | null {
  const base = path.posix.normalize(
    path.posix.join(path.posix.dirname(filePath), specifier),
  );
  const candidates = [
    base,
    ...[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].map(
      (extension) => `${base}${extension}`,
    ),
    ...[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].map(
      (extension) => `${base}/index${extension}`,
    ),
  ];
  return candidates.find((candidate) => inventoryPaths.has(candidate)) ?? null;
}

function formatSnippet(lines: string[], start: number, end: number): string {
  return lines
    .slice(start - 1, end)
    .map(
      (line, index) =>
        `${String(start + index).padStart(6)}|${redactPossibleSecret(line)}`,
    )
    .join("\n");
}

function redactPossibleSecret(line: string): string {
  const sanitized = line
    .replace(
      /(\b[a-z][a-z0-9+.-]*:\/\/)([^/@\s"']+):([^@\s"']*)@/gi,
      "$1[REDACTED]@",
    )
    .replace(/(\b[a-z][a-z0-9+.-]*:\/\/)([^/@\s"']+)@/gi, "$1[REDACTED]@");
  const assignment = sanitized.match(
    /^(\s*["']?[A-Za-z0-9_.-]*(?:secret|token|password|passwd|api[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]*["']?\s*[:=]\s*)(.+?)([,;]?\s*)$/i,
  );
  return assignment ? `${assignment[1]}[REDACTED]${assignment[3]}` : sanitized;
}

function selectRepresentativeCandidates(
  candidates: ReconCandidate[],
  limit: number,
): ReconCandidate[] {
  const selected: ReconCandidate[] = [];
  const seen = new Set<string>();
  for (const candidate of candidates) {
    const key = `${topLevel(candidate.path)}:${candidate.categories.join("+")}`;
    if (seen.has(key)) continue;
    seen.add(key);
    selected.push(candidate);
    if (selected.length >= limit) return selected;
  }
  for (const candidate of candidates) {
    if (selected.includes(candidate)) continue;
    selected.push(candidate);
    if (selected.length >= limit) break;
  }
  return selected;
}

function stratifiedPaths(files: InventoryFile[], limit: number): string[] {
  const selected: string[] = [];
  const seen = new Set<string>();
  const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
  for (const file of sorted) {
    const key = `${topLevel(file.path)}:${file.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    selected.push(file.path);
    if (selected.length >= limit) return selected;
  }
  for (const file of sorted) {
    if (selected.includes(file.path)) continue;
    selected.push(file.path);
    if (selected.length >= limit) break;
  }
  return selected;
}

function countBy<T>(
  items: T[],
  key: (item: T) => string,
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const value = key(item);
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return Object.fromEntries(
    Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)),
  );
}

function topLevel(filePath: string): string {
  return filePath.split("/")[0] || ".";
}

function truncateMiddle(value: string, maxCharacters: number): string {
  if (value.length <= maxCharacters) return value;
  const marker = "\n...[deterministically truncated]...\n";
  const side = Math.floor((maxCharacters - marker.length) / 2);
  return `${value.slice(0, side)}${marker}${value.slice(-side)}`;
}

function compareCandidates(a: ReconCandidate, b: ReconCandidate): number {
  return (
    a.path.localeCompare(b.path) ||
    a.line_start - b.line_start ||
    a.id.localeCompare(b.id)
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
