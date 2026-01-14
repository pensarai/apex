import {
  stepCountIs,
  type StreamTextResult,
  type ToolSet,
  type StreamTextOnStepFinishCallback,
  tool,
  hasToolCall,
} from "ai";
import { mapMessages, Messages } from "../../messages";
import { streamResponse, type AIModel } from "../../ai";
import { SYSTEM } from "./prompts";
import { createPentestTools } from "../tools";
import { Session } from "../../session";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import { detectOSAndEnhancePrompt } from "../utils";
import { getScopeDescription } from "../scope";
import { extractJavascriptEndpoints } from "./jsExtraction";
import { generateRandomName } from "../../../util/name";
import { nanoid } from "nanoid";
import {
  createBrowserTools,
  disconnectMcpClient,
} from "../browserTools/playwrightMcp";

export interface RunAgentProps {
  target: string;
  objective: string;
  model: AIModel;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  onToolTokenUsage?: (inputTokens: number, outputTokens: number) => void;
  abortSignal?: AbortSignal;
  session?: Session.SessionInfo;
  toolOverride?: {
    execute_command?: (opts: any) => Promise<any>;
    http_request?: (opts: any) => Promise<any>;
  };
}

export interface RunAgentResult extends StreamTextResult<ToolSet, never> {
  session: Session.ExecutionSession;
}

export async function runAgent(opts: RunAgentProps): Promise<{
  streamResult: RunAgentResult;
  session: Session.SessionInfo;
}> {
  const {
    target,
    model,
    onStepFinish,
    abortSignal,
    onToolTokenUsage,
    toolOverride,
  } = opts;

  // Create a new session for this attack surface analysis
  const session =
    opts.session ||
    (await Session.create({
      targets: [target],
      name: generateRandomName(),
    }));

  const subagentId = `attack-surface-${nanoid(6)}`;

  console.log(`Created attack surface session: ${session.id}`);
  console.log(`Session path: ${session.rootPath}`);

  // Read scope constraints and authentication instructions from session config
  const scopeConstraints = session.config?.scopeConstraints;
  const authenticationInstructions = session.config?.authenticationInstructions;

  // Log scope constraints if strict
  if (scopeConstraints?.strictScope) {
    console.log(`\n🎯 SCOPE CONSTRAINTS ENABLED:`);
    if (scopeConstraints.allowedHosts) {
      console.log(
        `   Allowed hosts: ${scopeConstraints.allowedHosts.join(", ")}`
      );
    }
    if (scopeConstraints.allowedPorts) {
      console.log(
        `   Allowed ports: ${scopeConstraints.allowedPorts.join(", ")}`
      );
    }
    console.log(`   Mode: STRICT - Only in-scope targets will be tested\n`);
  }

  // Create assets directory for attack surface agent
  const assetsPath = join(session.rootPath, "assets");
  if (!existsSync(assetsPath)) {
    mkdirSync(assetsPath, { recursive: true });
  }

  // Create tools with session context
  const { analyze_scan, execute_command, http_request, cve_lookup, smart_enumerate } = createPentestTools(
    session,
    model,
    toolOverride,
    onToolTokenUsage,
    abortSignal
  );

  // Create browser tools for JavaScript-heavy page analysis
  const evidenceDir = join(session.rootPath, "evidence");
  const browserTools = createBrowserTools(
    target,
    evidenceDir,
    "operator", // Attack surface uses operator mode (reconnaissance-focused)
    undefined,  // No logger needed for attack surface
    abortSignal
  );

  // Attack Surface specific tool: document_asset
  const document_asset = tool({
    name: "document_asset",
    description: `Document a discovered asset during attack surface analysis.
    
Assets are inventory items discovered during reconnaissance and saved to the session's assets folder.

Use this tool to document:
- Domains and subdomains
- Web applications and APIs  
- Infrastructure services (mail, DNS, VPN, databases)
- Cloud resources (S3 buckets, CDN, cloud storage)
- Development assets (dev/staging/test environments, CI/CD, repos)

Each asset creates a JSON file in the assets directory for tracking and analysis.`,
    inputSchema: z.object({
      assetName: z
        .string()
        .describe(
          "Unique name for the asset (e.g., 'example.com', 'api.example.com', 'admin-panel')"
        ),
      assetType: z
        .enum([
          "domain",
          "subdomain",
          "web_application",
          "api",
          "admin_panel",
          "infrastructure_service",
          "cloud_resource",
          "development_asset",
          "endpoint",
        ])
        .describe("Type of asset discovered"),
      description: z
        .string()
        .describe(
          "Detailed description of the asset including what it is and why it's relevant"
        ),
      details: z
        .preprocess(
          (val) => {
            // If a string is provided, try to parse it as JSON
            if (typeof val === "string") {
              try {
                return JSON.parse(val);
              } catch {
                // If parsing fails, return empty object
                return {};
              }
            }
            return val;
          },
          z.object({
            url: z.string().optional().describe("URL if applicable"),
            ip: z.string().optional().describe("IP address if known"),
            ports: z.array(z.number()).optional().describe("Open ports"),
            services: z
              .array(z.string())
              .optional()
              .describe("Running services (e.g., 'nginx 1.18', 'SSH 8.2')"),
            technology: z
              .array(z.string())
              .optional()
              .describe(
                "Technology stack (e.g., 'Node.js', 'Express', 'MongoDB')"
              ),
            endpoints: z
              .array(z.string())
              .optional()
              .describe("Discovered endpoints for web apps/APIs"),
            authentication: z
              .string()
              .optional()
              .describe("Authentication type if known"),
            status: z
              .union([z.string(), z.number()])
              .optional()
              .describe(
                "Status (active, inactive, redirect, error) or HTTP status code"
              ),
          })
        )
        .describe("Additional details about the asset"),
      riskLevel: z
        .preprocess((val) => {
          // Extract enum value from strings like ">HIGH", "HIGH!", "- CRITICAL", etc.
          if (typeof val === "string") {
            const upper = val.toUpperCase();
            // Try to extract the severity level
            if (upper.includes("CRITICAL")) return "CRITICAL";
            if (upper.includes("HIGH")) return "HIGH";
            if (upper.includes("MEDIUM")) return "MEDIUM";
            if (upper.includes("LOW")) return "LOW";
          }
          return val;
        }, z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]))
        .describe("Risk level: LOW-CRITICAL (exposed/sensitive)"),
      notes: z
        .string()
        .optional()
        .describe("Additional notes or observations about the asset"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Documenting discovered API endpoint')"
        ),
    }),
    execute: async (asset) => {
      // Create a sanitized filename from asset name
      const sanitizedName = asset.assetName
        .toLowerCase()
        .replace(/[^a-z0-9-_.]/g, "_");
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `asset_${sanitizedName}_${timestamp}.json`;
      const filepath = join(assetsPath, filename);

      // Create asset record with metadata
      const assetRecord = {
        ...asset,
        discoveredAt: new Date().toISOString(),
        sessionId: session.id,
        target: session.targets[0],
      };

      // Write asset to file
      writeFileSync(filepath, JSON.stringify(assetRecord, null, 2));

      return {
        success: true,
        assetName: asset.assetName,
        assetType: asset.assetType,
        riskLevel: asset.riskLevel,
        filepath,
        message: `Asset '${asset.assetName}' documented successfully in assets directory`,
      };
    },
  });

  // New tool: authenticate_and_maintain_session
  const authenticate_and_maintain_session = tool({
    name: "authenticate_and_maintain_session",
    description: `Authenticate with credentials and obtain a session cookie for subsequent authenticated requests.

Use this to:
- Test discovered credentials
- Obtain session cookies for authenticated exploration
- Access protected areas of the application`,
    inputSchema: z.object({
      loginUrl: z.string().describe("Login endpoint URL"),
      username: z.string().describe("Username to authenticate with"),
      password: z.string().describe("Password to authenticate with"),
      method: z
        .enum(["form_post", "json_post", "basic_auth"])
        .default("form_post")
        .describe("Authentication method"),
      usernameField: z
        .string()
        .default("username")
        .describe("Name of username field"),
      passwordField: z
        .string()
        .default("password")
        .describe("Name of password field"),
      additionalFields: z
        .record(z.string(), z.string())
        .optional()
        .describe("Additional form fields (e.g., csrf tokens)"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Authenticating with admin credentials')"
        ),
    }),
    execute: async (params) => {
      try {
        const {
          loginUrl,
          username,
          password,
          method,
          usernameField,
          passwordField,
          additionalFields,
        } = params;

        // Use http_request to perform authentication
        let authRequest: BunFetchRequestInit = { method: "POST" };

        if (method === "form_post") {
          const formData = {
            [usernameField]: username,
            [passwordField]: password,
            ...additionalFields,
          };
          authRequest.body = new URLSearchParams(formData).toString();
          authRequest.headers = {
            "Content-Type": "application/x-www-form-urlencoded",
          };
        } else if (method === "json_post") {
          authRequest.body = JSON.stringify({
            [usernameField]: username,
            [passwordField]: password,
            ...additionalFields,
          });
          authRequest.headers = { "Content-Type": "application/json" };
        } else if (method === "basic_auth") {
          const authHeader = Buffer.from(`${username}:${password}`).toString(
            "base64"
          );
          authRequest.headers = { Authorization: `Basic ${authHeader}` };
        }

        const result = await fetch(loginUrl, authRequest);

        // Extract session cookie from response
        const setCookieHeader = result.headers?.getSetCookie() || [];
        const sessionCookies = Array.isArray(setCookieHeader)
          ? setCookieHeader
          : [setCookieHeader];
        const cookieString = sessionCookies.join("; ");

        // Check if authentication was successful
        const authenticated =
          result.status >= 200 &&
          result.status < 400 &&
          cookieString.length > 0;

        // Save session info to session directory for reuse
        const sessionInfoPath = join(session.rootPath, "session-info.json");
        const sessionInfo = {
          authenticated,
          username,
          sessionCookie: cookieString,
          loginUrl,
          timestamp: new Date().toISOString(),
        };
        writeFileSync(sessionInfoPath, JSON.stringify(sessionInfo, null, 2));

        return {
          success: authenticated,
          authenticated,
          sessionCookie: cookieString,
          statusCode: result.status,
          message: authenticated
            ? `Successfully authenticated as ${username}. Session cookie saved for use with other tools.`
            : `Authentication failed. Status: ${result.status}.`,
        };
      } catch (error: any) {
        return {
          success: false,
          authenticated: false,
          message: `Authentication error: ${error.message}`,
        };
      }
    },
  });

  // New tool: extract_javascript_endpoints
  const extract_javascript_endpoints = tool({
    name: "extract_javascript_endpoints",
    description: `Extract endpoint URLs from JavaScript code in a page using pattern matching.

Uses regex patterns to find:
- AJAX calls ($.ajax, $.get, $.post)
- Fetch API calls
- Axios requests
- XMLHttpRequest calls
- URL assignments

Returns all discovered endpoint patterns.`,
    inputSchema: z.object({
      url: z.string().describe("URL of the page to analyze"),
      sessionCookie: z
        .string()
        .optional()
        .describe("Session cookie for authenticated pages"),
      includeExternalJS: z
        .boolean()
        .default(true)
        .describe("Whether to download and analyze external JS files"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Extracting API endpoints from JavaScript')"
        ),
    }),
    execute: async (params) => {
      return extractJavascriptEndpoints(params);
    },
  });

  // New tool: crawl_authenticated_area
  const crawl_authenticated_area = tool({
    name: "crawl_authenticated_area",
    description: `Recursively crawl web pages starting from a URL to discover links, forms, and JavaScript endpoints.

- Follows links to discover connected pages
- Extracts form actions
- Calls extract_javascript_endpoints on each discovered page
- Returns comprehensive map of discovered pages and endpoints`,
    inputSchema: z.object({
      startUrl: z.string().describe("Starting URL (e.g., /dashboard)"),
      sessionCookie: z
        .string()
        .describe("Session cookie from authenticate_and_maintain_session"),
      maxDepth: z.number().default(3).describe("Maximum crawl depth"),
      maxPages: z.number().default(50).describe("Maximum pages to visit"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Crawling authenticated dashboard area')"
        ),
    }),
    execute: async (params) => {
      try {
        const { startUrl, sessionCookie, maxDepth, maxPages } = params;

        const visited = new Set<string>();
        const toVisit: Array<{ url: string; depth: number }> = [
          { url: startUrl, depth: 0 },
        ];
        const pages: Array<any> = [];
        const allEndpoints = new Set<string>();

        while (toVisit.length > 0 && visited.size < maxPages) {
          const { url, depth } = toVisit.shift()!;

          if (visited.has(url) || depth > maxDepth) continue;
          visited.add(url);

          try {
            // Fetch page
            const pageResult = await fetch(url, {
              method: "GET",
              headers: {
                cookie: sessionCookie,
              },
            });

            if (pageResult.status >= 200 && pageResult.status < 400) {
              const html = pageResult.body || "";

              // Extract links
              const linkRegex = /<a[^>]+href=['"]([^'"]+)['"]/gi;
              const links: string[] = [];
              let linkMatch;
              while ((linkMatch = linkRegex.exec(html.toString())) !== null) {
                const link = linkMatch[1];
                if (link.startsWith("/") && !link.startsWith("//")) {
                  links.push(link);
                  if (!visited.has(link)) {
                    toVisit.push({ url: link, depth: depth + 1 });
                  }
                }
              }

              // Extract forms
              const formRegex = /<form[^>]+action=['"]([^'"]+)['"]/gi;
              const forms: string[] = [];
              let formMatch;
              while ((formMatch = formRegex.exec(html.toString())) !== null) {
                forms.push(formMatch[1]);
              }

              // Extract JavaScript endpoints from this page
              const jsEndpoints = await extractJavascriptEndpoints({
                url,
                sessionCookie,
                includeExternalJS: false,
              });

              if (jsEndpoints.endpoints) {
                jsEndpoints.endpoints.forEach((ep: any) =>
                  allEndpoints.add(ep.endpoint)
                );
              }

              pages.push({
                url,
                status: pageResult.status,
                links,
                forms,
                jsEndpoints: jsEndpoints.endpoints || [],
              });
            }
          } catch (error) {
            // Continue crawling even if one page fails
            console.error(`Error crawling ${url}:`, error);
          }
        }

        return {
          success: true,
          startUrl,
          pagesVisited: visited.size,
          totalPages: pages.length,
          pages,
          allDiscoveredEndpoints: Array.from(allEndpoints),
          message: `Crawled ${visited.size} pages. Discovered ${allEndpoints.size} unique endpoints from JavaScript.`,
        };
      } catch (error: any) {
        return {
          success: false,
          message: `Crawl error: ${error.message}`,
        };
      }
    },
  });

  // New tool: test_endpoint_variations
  const test_endpoint_variations = tool({
    name: "test_endpoint_variations",
    description: `Test multiple variations of an endpoint pattern with different parameters.

Use this to:
- Test an endpoint with multiple IDs to check for authorization issues
- Test related endpoints that follow similar patterns
- Systematically probe endpoint variations you've identified`,
    inputSchema: z.object({
      endpoints: z.array(z.string()).describe("Array of endpoint URLs to test"),
      sessionCookie: z
        .string()
        .optional()
        .describe("Session cookie if authentication required"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Testing endpoint variations for authorization issues')"
        ),
    }),
    execute: async (params) => {
      try {
        const { endpoints, sessionCookie } = params;

        const results: Array<any> = [];
        const accessible: Array<string> = [];
        const inaccessible: Array<string> = [];

        // Test each endpoint
        for (const endpoint of endpoints) {
          try {
            const request: BunFetchRequestInit = { method: "GET" };
            if (sessionCookie) {
              request.headers = { Cookie: sessionCookie };
            }

            const result = await fetch(endpoint, request);

            const body = await result.body?.text();

            results.push({
              endpoint,
              status: result.status,
              accessible: result.status >= 200 && result.status < 400,
              contentLength: body ? body.length : 0,
            });

            if (result.status >= 200 && result.status < 400) {
              accessible.push(endpoint);
            } else {
              inaccessible.push(endpoint);
            }
          } catch (error: any) {
            results.push({
              endpoint,
              status: 0,
              accessible: false,
              error: error.message,
            });
            inaccessible.push(endpoint);
          }
        }

        return {
          success: true,
          totalTested: endpoints.length,
          accessible: accessible.length,
          inaccessible: inaccessible.length,
          results,
          accessibleEndpoints: accessible,
          message: `Tested ${endpoints.length} endpoints. ${accessible.length} accessible, ${inaccessible.length} not accessible.`,
        };
      } catch (error: any) {
        return {
          success: false,
          message: `Endpoint testing error: ${error.message}`,
        };
      }
    },
  });

  // New tool: validate_discovery_completeness
  const validate_discovery_completeness = tool({
    name: "validate_discovery_completeness",
    description: `Check discovery completeness by analyzing what has been explored.

Returns a confidence score and identifies potential gaps based on:
- Whether authentication was attempted when credentials were found
- Coverage of authenticated areas
- JavaScript analysis coverage
- Resource pattern testing coverage`,
    inputSchema: z.object({
      discoveredEndpoints: z
        .array(z.string())
        .describe("All discovered endpoints"),
      authenticatedWithCredentials: z
        .boolean()
        .describe("Whether you authenticated with any discovered credentials"),
      pagesWithJSAnalyzed: z
        .array(z.string())
        .describe("Pages where you ran extract_javascript_endpoints"),
      credentialsFound: z
        .boolean()
        .describe("Whether any credentials were discovered"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Validating discovery completeness')"
        ),
    }),
    execute: async (params) => {
      const {
        discoveredEndpoints,
        authenticatedWithCredentials,
        pagesWithJSAnalyzed,
        credentialsFound,
      } = params;

      const gaps: Array<{
        gap: string;
        severity: string;
        recommendation: string;
      }> = [];
      let confidence = 100;

      // Check: Authenticated if credentials found
      if (credentialsFound && !authenticatedWithCredentials) {
        gaps.push({
          gap: "Credentials found but never used for authentication",
          severity: "CRITICAL",
          recommendation:
            "Use authenticate_and_maintain_session with discovered credentials, then use crawl_authenticated_area to explore authenticated sections",
        });
        confidence -= 40;
      }

      // Check: JavaScript analysis on authenticated pages
      if (authenticatedWithCredentials && pagesWithJSAnalyzed.length === 0) {
        gaps.push({
          gap: "Authenticated but no JavaScript analysis performed",
          severity: "CRITICAL",
          recommendation:
            "Use extract_javascript_endpoints on /dashboard, /orders, and other authenticated pages",
        });
        confidence -= 30;
      }

      // Check: CRUD enumeration for resource patterns
      const resourcePatterns = discoveredEndpoints.filter((ep) =>
        ep.includes("{id}")
      );
      if (
        resourcePatterns.length > 0 &&
        !discoveredEndpoints.some(
          (ep) => ep.includes("receipt") || ep.includes("archive")
        )
      ) {
        gaps.push({
          gap: "Resource patterns found but CRUD operations not enumerated",
          severity: "HIGH",
          recommendation:
            "Use enumerate_crud_operations to test all CRUD variations (receipt, archive, delete, edit, etc.)",
        });
        confidence -= 20;
      }

      // Check: Minimum endpoint discovery
      if (discoveredEndpoints.length < 5) {
        gaps.push({
          gap: "Very few endpoints discovered (less than 5)",
          severity: "MEDIUM",
          recommendation:
            "Ensure you crawled authenticated areas, analyzed JavaScript, and tested common paths",
        });
        confidence -= 10;
      }

      const complete = confidence >= 90;

      return {
        complete,
        confidence,
        gaps,
        summary: complete
          ? `Discovery is ${confidence}% complete. Ready to generate final report.`
          : `Discovery is only ${confidence}% complete. ${gaps.length} critical gaps found.`,
        readyForReport: complete,
        message: complete
          ? "Validation passed. You can now call create_attack_surface_report."
          : `Validation failed. Address these gaps before reporting: ${gaps
              .map((g) => g.gap)
              .join("; ")}`,
      };
    },
  });

  // Simplified answer schema for orchestrator agent
  const create_attack_surface_report = tool({
    name: "create_attack_surface_report",
    description: `Provide attack surface analysis results to the orchestrator agent.
    
Call this at the END of your analysis with:
- Summary statistics
- Discovered assets (simple list)
- ALL targets for deep testing with objectives. Do not prioritize any targets, optimize for breadth of testing.
- Key findings`,
    inputSchema: z.object({
      summary: z
        .object({
          totalAssets: z.number(),
          totalDomains: z.number(),
          analysisComplete: z.boolean(),
        })
        .describe("Summary statistics"),
      discoveredAssets: z
        .array(z.string())
        .describe(
          "List of discovered assets with descriptions. Format: 'example.com - Web server (nginx) - Ports 80,443'"
        ),
      targets: z
        .array(
          z.object({
            target: z.string().describe("Target URL, IP, or domain"),
            objective: z.string().describe("Pentest objective for this target"),
            rationale: z
              .string()
              .describe("Why this target needs deep testing"),
          })
        )
        .describe("ALL targets for deep penetration testing"),
      keyFindings: z.preprocess(
        (val) => (Array.isArray(val) ? val : [val]),
        z
          .array(z.string())
          .describe(
            "Key findings from reconnaissance. Format: '[SEVERITY] Finding description'"
          )
      ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Creating attack surface report')"
        ),
    }),
    execute: async (results) => {
      // Save the results to the session for the orchestrator to access
      const resultsPath = join(session.rootPath, "attack-surface-results.json");
      writeFileSync(resultsPath, JSON.stringify(results, null, 2));

      return {
        success: true,
        resultsPath,
        summary: results.summary,
        message: `Attack surface analysis complete. ${results.summary.totalAssets} assets identified for penetration testing.`,
      };
    },
  });

  // Build the enhanced prompt with target context
  const scopeDescription = getScopeDescription(scopeConstraints);

  const enhancedPrompt = `
TARGET: ${target}

Session Information:
- Session ID: ${session.id}
- Assets will be saved to: ${assetsPath}

${
  authenticationInstructions
    ? `<authentication_instructions>
${authenticationInstructions}

CRITICAL: When identifying targets for penetration testing, YOU MUST include the authentication information with EVERY target that requires authentication. Parse the above instructions and include them in the authenticationInfo field of each target in your final report.
</authentication_instructions>

`
    : ""
}
SCOPE CONSTRAINTS:
${scopeDescription}

Begin your attack surface analysis by:
1. Understanding the target scope (is it a domain, IP, URL, network range, or organization?)
2. Performing comprehensive reconnaissance to map the attack surface WITHIN SCOPE
3. Identifying assets, services, endpoints, and potential entry points
4. Call the smart_enumerate tool to aid in your discovery to find hidden routes and other resources
5. Categorizing discovered targets by type and risk level
6. Identify any core technologies being used, their versions, and calling the cve_lookup tool to see if there are any existing vulnerabilities in that version of the identified software
7. Document each significant asset using the document_asset tool
8. When complete, call the create_attack_surface_report tool

IMPORTANT SCOPING RULES:
${
  scopeConstraints?.strictScope
    ? `
- ONLY test URLs/endpoints within the allowed hosts and ports
- DO NOT perform port scans or subdomain enumeration outside the target
- DO NOT test infrastructure services (databases, caches, etc.)
- Focus ONLY on the web application at the target URL
`
    : `
- You may discover and test any related targets
- Prioritize in-scope targets but can explore adjacent services
`
}

Your goal is to provide a comprehensive map of the attack surface, NOT to perform deep exploitation.
Focus on breadth of discovery rather than depth of testing.

Document all discovered assets using the document_asset tool - this creates an inventory of:
- Domains and subdomains (if in scope)
- Web applications and APIs
- Endpoints and routes
- Authentication mechanisms

You MUST provide the final report using create_attack_surface_report tool.
`.trim();

  const systemPrompt = detectOSAndEnhancePrompt(SYSTEM);

  const streamResult = streamResponse({
    prompt: enhancedPrompt,
    system: systemPrompt,
    model,
    tools: {
      analyze_scan,
      document_asset,
      execute_command,
      http_request,
      authenticate_and_maintain_session,
      extract_javascript_endpoints,
      crawl_authenticated_area,
      test_endpoint_variations,
      validate_discovery_completeness,
      create_attack_surface_report,
      cve_lookup,
      smart_enumerate,
      // Browser automation tools for JavaScript-heavy apps and SPAs
      ...browserTools,
    },
    stopWhen: stepCountIs(10000),
    toolChoice: "auto", // Let the model decide when to use tools vs respond
    onStepFinish,
    abortSignal,
  });

  // Attach the session directly to the stream result object
  (streamResult as any).session = session;

  return { streamResult: streamResult as RunAgentResult, session };
}
