#!/usr/bin/env bun

/**
 * pensar apps — Manage the workspace attack surface (apps & endpoints).
 *
 * All commands operate on the selected workspace (set via `pensar login`).
 *
 * Usage:
 *   pensar apps                                             List apps
 *   pensar apps get <appId>                                 Show app details
 *   pensar apps create --name N --description D [opts]      Create an app
 *   pensar apps update <appId> [opts]                       Update app fields
 *   pensar apps delete <appId>                              Delete an app
 *   pensar apps domains                                     List domains
 *   pensar apps domain-create <domain>                      Create a domain
 *   pensar apps endpoints <appId> [filters]                 List endpoints
 *   pensar apps endpoint <endpointId>                       Show endpoint
 *   pensar apps endpoint-create <appId> --endpoint E ...    Create endpoint
 *   pensar apps endpoint-update <endpointId> [opts]         Update endpoint
 *   pensar apps endpoint-delete <endpointId>                Delete endpoint
 */

import {
  type ApplicationType,
  type CreateAppInput,
  type CreateEndpointInput,
  createApp,
  createDomain,
  createEndpoint,
  deleteApp,
  deleteEndpoint,
  ENDPOINT_TRANSPORTS,
  type EndpointTransport,
  type EndpointType,
  getApp,
  getEndpoint,
  listApps,
  listDomains,
  listEndpoints,
  searchApps,
  searchEndpoints,
  type UpdateAppInput,
  type UpdateEndpointInput,
  updateApp,
  updateEndpoint,
} from "../core/api";

const APPLICATION_TYPES: ApplicationType[] = [
  "ui",
  "api-service",
  "web-application",
  "full-stack",
  "domain",
  "subdomain",
  "database",
  "cloud-resource",
  "storage",
];

const ENDPOINT_TYPES: EndpointType[] = [
  "api-endpoint",
  "web-endpoint",
  "auth-endpoint",
  "database",
  "file-storage",
  "asset",
];

function getFlag(flag: string, argv: string[]): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : undefined;
}

function getAllFlags(flag: string, argv: string[]): string[] {
  const values: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const next = argv[i + 1];
    if (argv[i] === flag && next !== undefined) {
      values.push(next);
    }
  }
  return values;
}

function hasFlag(flag: string, argv: string[]): boolean {
  return argv.includes(flag);
}

function parseAppType(value: string | undefined): ApplicationType | undefined {
  if (value === undefined) return undefined;
  if (!APPLICATION_TYPES.includes(value as ApplicationType)) {
    throw new Error(
      `Invalid --type "${value}". Must be one of: ${APPLICATION_TYPES.join(", ")}`,
    );
  }
  return value as ApplicationType;
}

function parseEndpointType(
  value: string | undefined,
): EndpointType | undefined {
  if (value === undefined) return undefined;
  if (!ENDPOINT_TYPES.includes(value as EndpointType)) {
    throw new Error(
      `Invalid --type "${value}". Must be one of: ${ENDPOINT_TYPES.join(", ")}`,
    );
  }
  return value as EndpointType;
}

function parseTransport(
  value: string | undefined,
): EndpointTransport | undefined {
  if (value === undefined) return undefined;
  if (!ENDPOINT_TRANSPORTS.includes(value as EndpointTransport)) {
    throw new Error(
      `Invalid --transport "${value}". Must be one of: ${ENDPOINT_TRANSPORTS.join(", ")}`,
    );
  }
  return value as EndpointTransport;
}

function parseInteger(
  flag: string,
  value: string | undefined,
): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    throw new Error(`${flag} must be an integer (got "${value}")`);
  }
  return n;
}

function parseNumber(
  flag: string,
  value: string | undefined,
): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n)) {
    throw new Error(`${flag} must be a number (got "${value}")`);
  }
  return n;
}

function showHelp(): void {
  console.log(`pensar apps — Manage the workspace attack surface (apps & endpoints)

All commands operate on the selected workspace (set via \`pensar login\`).

Usage:
  pensar apps                                              List apps in the workspace
  pensar apps get <appId>                                  Show app details
  pensar apps create [options]                             Create an app
  pensar apps update <appId> [options]                     Update an app
  pensar apps delete <appId>                               Delete an app
  pensar apps domains                                      List workspace domains
  pensar apps domain-create <domain>                       Create/resolve a domain
  pensar apps endpoints <appId> [filters]                  List endpoints
  pensar apps endpoint <endpointId>                        Show endpoint details
  pensar apps endpoint-create <appId> [options]            Create an endpoint
  pensar apps endpoint-update <endpointId> [options]       Update an endpoint
  pensar apps endpoint-delete <endpointId>                 Delete an endpoint
  pensar apps search <query> [options]                     Substring-search apps
  pensar apps search-endpoints <query> [options]           Substring-search endpoints

App fields (create requires --name and --description):
  --name <text>                Application name
  --description <text>         Application description
  --type <type>                One of: ${APPLICATION_TYPES.join(", ")}
  --framework <text>           Framework / runtime hint
  --domain <id>                Linked domain UUID (see "apps domains")
  --disallowed-actions <text>  Free-form disallowed actions notes

Domains:
  API-created domains are canonicalized and created idempotently by Console.
  They stay unverified and do not start reconnaissance.

List pagination (for "apps" and "endpoints <appId>"):
  --limit <n>                  Page size (default 100, max 200)
  --offset <n>                 Page offset (default 0)
  Responses include { ..., hasMore, limit, offset }; iterate by
  incrementing --offset by --limit until hasMore is false.

Endpoint filters (for "endpoints"):
  --type <type>                One of: ${ENDPOINT_TYPES.join(", ")}
  --min-risk <score>           Minimum risk score (0–10)

Search options (scoped to the workspace):
  --app <id>                   search-endpoints only: scope to a single app
  --type <type>                Filter by application or endpoint type
  --min-risk <score>           Endpoint search only: minimum risk score
  --auth-required              Endpoint search only: only auth-required endpoints
  --no-auth-required           Endpoint search only: only public endpoints
  --limit <n>                  Page size (default 50, max 200)
  --offset <n>                 Page offset

Endpoint fields (create requires --endpoint and --description):
  --app <id>                   endpoint-update only: move the endpoint to a
                               different application (UUID) in the workspace
  --endpoint <text>            Endpoint path / URL / route
  --description <text>         Endpoint description
  --type <type>                One of: ${ENDPOINT_TYPES.join(", ")}
  --transport <transport>      One of: ${ENDPOINT_TRANSPORTS.join(", ")}
                               (defaults to http when omitted)
  --location <text>            Source file (whitebox)
  --start-line <n>             Start line number
  --end-line <n>               End line number
  --objective <text>           Repeatable: testing objective for the endpoint
  --auth-required              Mark endpoint as authentication-required
  --no-auth-required           Mark endpoint as not requiring auth
  --auth-details <text>        Free-form auth details
  --business-logic <text>      Business-logic notes
  --threat-model <text>        Per-endpoint threat model notes

Options:
  -h, --help                   Show this help message`);
}

function parseAppCreateOptions(argv: string[]): CreateAppInput {
  const name = getFlag("--name", argv);
  const description = getFlag("--description", argv);
  if (!name) throw new Error("--name is required");
  if (description === undefined) throw new Error("--description is required");

  const type = parseAppType(getFlag("--type", argv));
  const framework = getFlag("--framework", argv);
  const domainId = getFlag("--domain", argv);
  const disallowedActions = getFlag("--disallowed-actions", argv);

  return {
    name,
    description,
    ...(type !== undefined ? { type } : {}),
    ...(framework !== undefined ? { framework } : {}),
    ...(domainId !== undefined ? { domainId } : {}),
    ...(disallowedActions !== undefined ? { disallowedActions } : {}),
  };
}

function parseAppUpdateOptions(argv: string[]): UpdateAppInput {
  const update: UpdateAppInput = {};
  const name = getFlag("--name", argv);
  if (name !== undefined) update.name = name;
  const description = getFlag("--description", argv);
  if (description !== undefined) update.description = description;
  const type = parseAppType(getFlag("--type", argv));
  if (type !== undefined) update.type = type;
  const framework = getFlag("--framework", argv);
  if (framework !== undefined) update.framework = framework;
  const domain = getFlag("--domain", argv);
  if (domain !== undefined) update.domainId = domain;
  const disallowed = getFlag("--disallowed-actions", argv);
  if (disallowed !== undefined) update.disallowedActions = disallowed;
  return update;
}

function parseAuthenticationRequiredFlag(
  argv: string[],
): { required: boolean; details?: string } | undefined {
  const yes = hasFlag("--auth-required", argv);
  const no = hasFlag("--no-auth-required", argv);
  const details = getFlag("--auth-details", argv);
  if (!yes && !no && details === undefined) return undefined;
  if (yes && no) {
    throw new Error(
      "--auth-required and --no-auth-required are mutually exclusive",
    );
  }
  return {
    required: yes,
    ...(details !== undefined ? { details } : {}),
  };
}

function parseEndpointCreateOptions(argv: string[]): CreateEndpointInput {
  const endpoint = getFlag("--endpoint", argv);
  const description = getFlag("--description", argv);
  if (!endpoint) throw new Error("--endpoint is required");
  if (description === undefined) throw new Error("--description is required");

  const type = parseEndpointType(getFlag("--type", argv));
  const transport = parseTransport(getFlag("--transport", argv));
  const location = getFlag("--location", argv);
  const startLineNumber = parseInteger(
    "--start-line",
    getFlag("--start-line", argv),
  );
  const endLineNumber = parseInteger("--end-line", getFlag("--end-line", argv));
  const objectives = getAllFlags("--objective", argv);
  const authenticationRequired = parseAuthenticationRequiredFlag(argv);
  const businessLogic = getFlag("--business-logic", argv);
  const threatModel = getFlag("--threat-model", argv);

  return {
    endpoint,
    description,
    ...(type !== undefined ? { type } : {}),
    ...(transport !== undefined ? { transport } : {}),
    ...(location !== undefined ? { location } : {}),
    ...(startLineNumber !== undefined ? { startLineNumber } : {}),
    ...(endLineNumber !== undefined ? { endLineNumber } : {}),
    ...(objectives.length > 0 ? { objectives } : {}),
    ...(authenticationRequired !== undefined ? { authenticationRequired } : {}),
    ...(businessLogic !== undefined ? { businessLogic } : {}),
    ...(threatModel !== undefined ? { threatModel } : {}),
  };
}

function parseEndpointUpdateOptions(argv: string[]): UpdateEndpointInput {
  const update: UpdateEndpointInput = {};
  const applicationId = getFlag("--app", argv);
  if (applicationId !== undefined) update.applicationId = applicationId;
  const endpoint = getFlag("--endpoint", argv);
  if (endpoint !== undefined) update.endpoint = endpoint;
  const description = getFlag("--description", argv);
  if (description !== undefined) update.description = description;
  const type = parseEndpointType(getFlag("--type", argv));
  if (type !== undefined) update.type = type;
  const transport = parseTransport(getFlag("--transport", argv));
  if (transport !== undefined) update.transport = transport;
  const location = getFlag("--location", argv);
  if (location !== undefined) update.location = location;
  const startLine = parseInteger("--start-line", getFlag("--start-line", argv));
  if (startLine !== undefined) update.startLineNumber = startLine;
  const endLine = parseInteger("--end-line", getFlag("--end-line", argv));
  if (endLine !== undefined) update.endLineNumber = endLine;
  const objectives = getAllFlags("--objective", argv);
  if (objectives.length > 0) update.objectives = objectives;
  const auth = parseAuthenticationRequiredFlag(argv);
  if (auth !== undefined) update.authenticationRequired = auth;
  const businessLogic = getFlag("--business-logic", argv);
  if (businessLogic !== undefined) update.businessLogic = businessLogic;
  const threatModel = getFlag("--threat-model", argv);
  if (threatModel !== undefined) update.threatModel = threatModel;
  return update;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const sub = args[0];

  if (sub === "--help" || sub === "-h" || sub === "help") {
    showHelp();
    return;
  }

  try {
    if (sub === "get") {
      const appId = args[1];
      if (!appId) {
        console.error("Error: app ID is required");
        console.error("Usage: pensar apps get <appId>");
        process.exit(1);
      }
      const app = await getApp(appId);
      console.log(JSON.stringify(app, null, 2));
    } else if (sub === "create") {
      const opts = parseAppCreateOptions(args);
      const result = await createApp(opts);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "update") {
      const appId = args[1];
      if (!appId) {
        console.error("Error: app ID is required");
        console.error("Usage: pensar apps update <appId> [options]");
        process.exit(1);
      }
      const opts = parseAppUpdateOptions(args);
      const result = await updateApp(appId, opts);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "delete") {
      const appId = args[1];
      if (!appId) {
        console.error("Error: app ID is required");
        console.error("Usage: pensar apps delete <appId>");
        process.exit(1);
      }
      const result = await deleteApp(appId);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "domains") {
      const result = await listDomains();
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "domain-create") {
      const url = args[1];
      if (!url) {
        console.error("Error: domain is required");
        console.error("Usage: pensar apps domain-create <domain>");
        process.exit(1);
      }
      const result = await createDomain({ url });
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "endpoints") {
      const appId = args[1];
      if (!appId) {
        console.error("Error: app ID is required");
        console.error("Usage: pensar apps endpoints <appId> [filters]");
        process.exit(1);
      }
      const type = parseEndpointType(getFlag("--type", args));
      const minRiskScore = parseNumber(
        "--min-risk",
        getFlag("--min-risk", args),
      );
      const limit = parseInteger("--limit", getFlag("--limit", args));
      const offset = parseInteger("--offset", getFlag("--offset", args));
      const filters = {
        ...(type !== undefined ? { type } : {}),
        ...(minRiskScore !== undefined ? { minRiskScore } : {}),
        ...(limit !== undefined ? { limit } : {}),
        ...(offset !== undefined ? { offset } : {}),
      };
      const result = await listEndpoints(appId, filters);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "endpoint") {
      const endpointId = args[1];
      if (!endpointId) {
        console.error("Error: endpoint ID is required");
        console.error("Usage: pensar apps endpoint <endpointId>");
        process.exit(1);
      }
      const result = await getEndpoint(endpointId);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "endpoint-create") {
      const appId = args[1];
      if (!appId) {
        console.error("Error: app ID is required");
        console.error(
          "Usage: pensar apps endpoint-create <appId> --endpoint E --description D",
        );
        process.exit(1);
      }
      const opts = parseEndpointCreateOptions(args);
      const result = await createEndpoint(appId, opts);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "endpoint-update") {
      const endpointId = args[1];
      if (!endpointId) {
        console.error("Error: endpoint ID is required");
        console.error(
          "Usage: pensar apps endpoint-update <endpointId> [options]",
        );
        process.exit(1);
      }
      const opts = parseEndpointUpdateOptions(args);
      const result = await updateEndpoint(endpointId, opts);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "endpoint-delete") {
      const endpointId = args[1];
      if (!endpointId) {
        console.error("Error: endpoint ID is required");
        console.error("Usage: pensar apps endpoint-delete <endpointId>");
        process.exit(1);
      }
      const result = await deleteEndpoint(endpointId);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "search") {
      const query = args[1];
      if (!query || query.startsWith("--")) {
        console.error("Error: search query is required");
        console.error("Usage: pensar apps search <query> [options]");
        process.exit(1);
      }
      const type = parseAppType(getFlag("--type", args));
      const limit = parseInteger("--limit", getFlag("--limit", args));
      const offset = parseInteger("--offset", getFlag("--offset", args));
      const result = await searchApps(query, {
        ...(type !== undefined ? { type } : {}),
        ...(limit !== undefined ? { limit } : {}),
        ...(offset !== undefined ? { offset } : {}),
      });
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "search-endpoints") {
      const query = args[1];
      if (!query || query.startsWith("--")) {
        console.error("Error: search query is required");
        console.error("Usage: pensar apps search-endpoints <query> [options]");
        process.exit(1);
      }
      const applicationId = getFlag("--app", args);
      const type = parseEndpointType(getFlag("--type", args));
      const minRiskScore = parseNumber(
        "--min-risk",
        getFlag("--min-risk", args),
      );
      const authRequired = hasFlag("--auth-required", args)
        ? true
        : hasFlag("--no-auth-required", args)
          ? false
          : undefined;
      const limit = parseInteger("--limit", getFlag("--limit", args));
      const offset = parseInteger("--offset", getFlag("--offset", args));
      const result = await searchEndpoints(query, {
        ...(applicationId !== undefined ? { applicationId } : {}),
        ...(type !== undefined ? { type } : {}),
        ...(minRiskScore !== undefined ? { minRiskScore } : {}),
        ...(authRequired !== undefined ? { authRequired } : {}),
        ...(limit !== undefined ? { limit } : {}),
        ...(offset !== undefined ? { offset } : {}),
      });
      console.log(JSON.stringify(result, null, 2));
    } else if (!sub || sub === "list" || sub.startsWith("--")) {
      // Default: list apps in the selected workspace.
      const limit = parseInteger("--limit", getFlag("--limit", args));
      const offset = parseInteger("--offset", getFlag("--offset", args));
      const result = await listApps({
        ...(limit !== undefined ? { limit } : {}),
        ...(offset !== undefined ? { offset } : {}),
      });
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.error(`Error: Unknown subcommand "${sub}"`);
      showHelp();
      process.exit(1);
    }
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
}

main();
