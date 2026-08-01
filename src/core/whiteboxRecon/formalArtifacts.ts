import { readFile } from "node:fs/promises";
import path from "node:path";
import { isMap, isScalar, isSeq, LineCounter, parseDocument } from "yaml";
import { throwIfReconAborted } from "./abort";
import { normalizeRepositoryPath } from "./identity";
import type {
  ReconApplication,
  ReconSurface,
  RepositoryInventory,
  UnresolvedItem,
} from "./types";

export interface FormalArtifactResult {
  surfaces: ReconSurface[];
  unresolved: UnresolvedItem[];
}

const HTTP_METHODS = new Set([
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "options",
  "head",
  "trace",
]);

export async function extractFormalArtifactSurfaces(
  inventory: RepositoryInventory,
  applications: ReconApplication[],
  abortSignal?: AbortSignal,
): Promise<FormalArtifactResult> {
  const surfaces: ReconSurface[] = [];
  const unresolved: UnresolvedItem[] = [];
  for (const file of inventory.files) {
    throwIfReconAborted(abortSignal);
    if (
      file.relevance !== "analyze" ||
      (file.kind !== "schema" && file.kind !== "api-spec")
    ) {
      continue;
    }
    const applicationId = applicationForPath(file.path, applications);
    if (!applicationId) {
      unresolved.push({
        kind: "application-assignment",
        summary: `Formal interfaces in ${file.path} have no unique application`,
        source_files: [file.path],
        reason: "formal-artifact-application-ambiguous",
      });
      continue;
    }
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
        summary: `Could not read formal artifact ${file.path}`,
        source_files: [file.path],
        reason: error instanceof Error ? error.message : String(error),
      });
      continue;
    }
    try {
      if (/\.(?:graphql|gql)$/i.test(file.path)) {
        surfaces.push(...extractGraphql(file.path, content, applicationId));
      } else if (/\.proto$/i.test(file.path)) {
        surfaces.push(...extractProto(file.path, content, applicationId));
      } else if (file.kind === "api-spec") {
        surfaces.push(...extractOpenApi(file.path, content, applicationId));
      }
    } catch (error) {
      unresolved.push({
        kind: "surface",
        summary: `Could not parse formal artifact ${file.path}`,
        source_files: [file.path],
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return { surfaces, unresolved };
}

function extractGraphql(
  sourceFile: string,
  content: string,
  applicationId: string,
): ReconSurface[] {
  const surfaces: ReconSurface[] = [];
  const lines = content.split("\n");
  let operationType: "Query" | "Mutation" | "Subscription" | undefined;
  let depth = 0;
  lines.forEach((line, index) => {
    const declaration = line.match(
      /^\s*(?:extend\s+)?type\s+(Query|Mutation|Subscription)\b/,
    );
    if (declaration) {
      operationType = declaration[1] as typeof operationType;
      depth = braceDelta(line);
      return;
    }
    if (!operationType) return;
    const field = line.match(
      /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:\s*/,
    );
    if (field?.[1] && !line.trimStart().startsWith("#")) {
      surfaces.push({
        application_id: applicationId,
        type: "graphql",
        method: operationType.toUpperCase(),
        path_or_name: `${operationType}.${field[1]}`,
        source_file: sourceFile,
        source_line: index + 1,
      });
    }
    depth += braceDelta(line);
    if (depth <= 0) operationType = undefined;
  });
  return surfaces;
}

function extractProto(
  sourceFile: string,
  content: string,
  applicationId: string,
): ReconSurface[] {
  const surfaces: ReconSurface[] = [];
  const lines = content.split("\n");
  let service: string | undefined;
  let depth = 0;
  lines.forEach((line, index) => {
    const declaration = line.match(/^\s*service\s+([A-Za-z_][A-Za-z0-9_]*)\b/);
    if (declaration?.[1]) {
      service = declaration[1];
      depth = braceDelta(line);
      return;
    }
    if (!service) return;
    const rpc = line.match(/^\s*rpc\s+([A-Za-z_][A-Za-z0-9_]*)\b/);
    if (rpc?.[1]) {
      surfaces.push({
        application_id: applicationId,
        type: "grpc",
        method: "RPC",
        path_or_name: `${service}.${rpc[1]}`,
        source_file: sourceFile,
        source_line: index + 1,
      });
    }
    depth += braceDelta(line);
    if (depth <= 0) service = undefined;
  });
  return surfaces;
}

function extractOpenApi(
  sourceFile: string,
  content: string,
  applicationId: string,
): ReconSurface[] {
  const surfaces: ReconSurface[] = [];
  const lineCounter = new LineCounter();
  const document = parseDocument(content, { lineCounter });
  if (document.errors.length > 0) {
    throw new Error(document.errors.map((error) => error.message).join("; "));
  }
  const paths = document.get("paths", true);
  if (!isMap(paths)) return surfaces;
  const basePath = openApiBasePath(document);
  for (const pathPair of paths.items) {
    const route = scalarString(pathPair.key);
    if (!route?.startsWith("/") || !isMap(pathPair.value)) continue;
    for (const operationPair of pathPair.value.items) {
      const method = scalarString(operationPair.key)?.toLowerCase();
      if (!method || !HTTP_METHODS.has(method)) continue;
      surfaces.push({
        application_id: applicationId,
        type: "http",
        method: method.toUpperCase(),
        path_or_name: joinRoute(basePath, route),
        source_file: sourceFile,
        source_line: nodeLine(operationPair.key, lineCounter),
      });
    }
  }
  return surfaces;
}

function openApiBasePath(document: ReturnType<typeof parseDocument>): string {
  const swaggerBasePath = scalarString(document.get("basePath", true));
  if (swaggerBasePath?.startsWith("/")) return swaggerBasePath;
  const servers = document.get("servers", true);
  if (!isSeq(servers)) return "";
  const firstServer = servers.items[0];
  if (!isMap(firstServer)) return "";
  const serverUrl = scalarString(firstServer.get("url", true));
  if (!serverUrl) return "";
  try {
    return new URL(serverUrl, "https://whitebox.invalid").pathname.replace(
      /\/$/,
      "",
    );
  } catch {
    return "";
  }
}

function scalarString(value: unknown): string | null {
  return isScalar(value) && typeof value.value === "string"
    ? value.value
    : null;
}

function nodeLine(value: unknown, lineCounter: LineCounter): number {
  if (
    typeof value !== "object" ||
    value === null ||
    !("range" in value) ||
    !Array.isArray(value.range) ||
    typeof value.range[0] !== "number"
  ) {
    return 0;
  }
  return lineCounter.linePos(value.range[0]).line;
}

function joinRoute(basePath: string, route: string): string {
  if (!basePath || basePath === "/") return route;
  return `${basePath.replace(/\/$/, "")}/${route.replace(/^\//, "")}`;
}

function applicationForPath(
  filePath: string,
  applications: ReconApplication[],
): string | null {
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

function braceDelta(line: string): number {
  return [...line].reduce(
    (total, character) =>
      total + (character === "{" ? 1 : character === "}" ? -1 : 0),
    0,
  );
}
