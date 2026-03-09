import type { ModelMessage } from "ai";

/**
 * Rough token estimate based on character count.
 * JSON.stringify(messages).length / 4 is a fast approximation.
 */
export function estimateTokens(messages: ModelMessage[]): number {
  return Math.ceil(JSON.stringify(messages).length / 4);
}

/**
 * Trim old tool results from a message array to reduce context size.
 *
 * Keeps the most recent `keepRecent` tool-call/tool-result pairs intact.
 * For older pairs, replaces the tool result output with a one-liner summary.
 * Preserves ToolCallPart as-is (small — just tool name + args).
 * Maintains the SDK's required tool-call/tool-result pairing.
 */
export function trimToolResults(
  messages: ModelMessage[],
  keepRecent: number = 6,
): ModelMessage[] {
  // Deep clone to avoid mutating the original
  const cloned: ModelMessage[] = JSON.parse(JSON.stringify(messages));

  // Collect all tool-call IDs in order of appearance
  const toolCallIds: string[] = [];

  for (const msg of cloned) {
    if (!Array.isArray(msg.content)) continue;
    for (const part of msg.content as Record<string, unknown>[]) {
      if (part.type === "tool-call" && part.toolCallId) {
        toolCallIds.push(part.toolCallId as string);
      }
    }
  }

  // The IDs to keep intact (most recent N)
  const keepSet = new Set(toolCallIds.slice(-keepRecent));

  // Walk messages and trim old tool results
  for (const msg of cloned) {
    if (!Array.isArray(msg.content)) continue;

    for (const part of msg.content as Record<string, unknown>[]) {
      if (
        part.type === "tool-result" &&
        part.toolCallId &&
        !keepSet.has(part.toolCallId as string)
      ) {
        // Find the corresponding tool call to get description/name
        let toolName = "unknown_tool";
        let toolDescription = "";

        for (const m of cloned) {
          if (!Array.isArray(m.content)) continue;
          for (const p of m.content as Record<string, unknown>[]) {
            if (
              p.type === "tool-call" &&
              p.toolCallId === part.toolCallId
            ) {
              toolName = (p.toolName as string) || "unknown_tool";
              try {
                const args =
                  typeof p.args === "string"
                    ? JSON.parse(p.args)
                    : p.args;
                toolDescription =
                  (args as Record<string, unknown>)
                    ?.toolCallDescription as string || "";
              } catch {
                // ignore parse errors
              }
              break;
            }
          }
          if (toolName !== "unknown_tool") break;
        }

        // Determine success/fail from the result
        let status = "completed";
        try {
          const resultStr =
            typeof part.result === "string"
              ? part.result
              : JSON.stringify(part.result);
          if (
            resultStr.includes('"success":false') ||
            resultStr.includes('"error"') ||
            resultStr.includes("Command failed") ||
            resultStr.includes("Exit code:")
          ) {
            status = "failed";
          }
        } catch {
          // ignore
        }

        const desc = toolDescription || toolName;
        const summary = `[Trimmed] ${desc} — ${status}. Output trimmed to save context.`;

        // Replace the output
        if (Array.isArray(part.content)) {
          part.content = [{ type: "text", text: summary }];
        } else {
          part.result = summary;
        }
      }
    }
  }

  return cloned;
}

/**
 * Extract structured pentest findings by scanning messages for known patterns.
 * Used before summarization to preserve critical discoveries.
 */
export function extractPentestFindings(messages: ModelMessage[]): string {
  const findings: {
    vulnerabilities: string[];
    assets: string[];
    credentials: string[];
    flags: string[];
    services: string[];
  } = {
    vulnerabilities: [],
    assets: [],
    credentials: [],
    flags: [],
    services: [],
  };

  for (const msg of messages) {
    if (!Array.isArray(msg.content)) {
      const text = typeof msg.content === "string" ? msg.content : "";
      scanTextForFindings(text, findings);
      continue;
    }

    for (const part of msg.content as Record<string, unknown>[]) {
      // Check tool results from document_vulnerability
      if (
        part.type === "tool-result" &&
        part.toolName === "document_vulnerability"
      ) {
        try {
          const result =
            typeof part.result === "string"
              ? JSON.parse(part.result as string)
              : part.result;
          if (result?.title) {
            findings.vulnerabilities.push(
              `[${result.severity || "?"}] ${result.title} — endpoint: ${result.endpoint || "?"}`,
            );
          }
        } catch {
          // ignore
        }
      }

      // Check tool results from document_asset
      if (
        part.type === "tool-result" &&
        part.toolName === "document_asset"
      ) {
        try {
          const result =
            typeof part.result === "string"
              ? JSON.parse(part.result as string)
              : part.result;
          if (result?.assetType || result?.url) {
            findings.assets.push(
              `${result.assetType || "asset"}: ${result.url || result.name || "?"}`,
            );
          }
        } catch {
          // ignore
        }
      }

      // Scan text content for patterns
      if (part.type === "text" && part.text) {
        scanTextForFindings(part.text as string, findings);
      }

      // Scan tool result text
      if (part.type === "tool-result") {
        const resultText =
          typeof part.result === "string"
            ? part.result
            : JSON.stringify(part.result ?? "");
        scanTextForFindings(resultText as string, findings);
      }
    }
  }

  // Deduplicate
  for (const key of Object.keys(findings) as (keyof typeof findings)[]) {
    findings[key] = [...new Set(findings[key])];
  }

  // Build structured output
  const sections: string[] = [];

  if (findings.vulnerabilities.length > 0) {
    sections.push(
      `### Confirmed Vulnerabilities\n${findings.vulnerabilities.map((v) => `- ${v}`).join("\n")}`,
    );
  }
  if (findings.services.length > 0) {
    sections.push(
      `### Discovered Services/Ports\n${findings.services.map((s) => `- ${s}`).join("\n")}`,
    );
  }
  if (findings.assets.length > 0) {
    sections.push(
      `### Discovered Assets\n${findings.assets.map((a) => `- ${a}`).join("\n")}`,
    );
  }
  if (findings.credentials.length > 0) {
    sections.push(
      `### Credentials/Tokens Found\n${findings.credentials.map((c) => `- ${c}`).join("\n")}`,
    );
  }
  if (findings.flags.length > 0) {
    sections.push(
      `### Flags Found\n${findings.flags.map((f) => `- ${f}`).join("\n")}`,
    );
  }

  return sections.length > 0 ? sections.join("\n\n") : "";
}

function scanTextForFindings(
  text: string,
  findings: {
    vulnerabilities: string[];
    assets: string[];
    credentials: string[];
    flags: string[];
    services: string[];
  },
): void {
  if (!text || text.length === 0) return;

  // Flags
  const flagMatches = text.match(/FLAG\{[^}]*\}/g);
  if (flagMatches) {
    for (const flag of flagMatches) {
      findings.flags.push(flag);
    }
  }

  // Credentials / passwords / tokens
  const credPatterns = [
    /password[:\s=]+["']?([^\s"']{3,})/gi,
    /token[:\s=]+["']?([^\s"']{8,})/gi,
    /api[_-]?key[:\s=]+["']?([^\s"']{8,})/gi,
    /secret[:\s=]+["']?([^\s"']{8,})/gi,
  ];
  for (const pattern of credPatterns) {
    const matches = text.matchAll(pattern);
    for (const match of matches) {
      const cred = match[0].substring(0, 100); // Cap length
      findings.credentials.push(cred);
    }
  }

  // Open ports / services (from nmap-style output)
  const portMatches = text.match(/(\d+)\/(tcp|udp)\s+open\s+\S+/g);
  if (portMatches) {
    for (const port of portMatches) {
      findings.services.push(port);
    }
  }
}
