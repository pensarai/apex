#!/usr/bin/env bun
import { render } from "@opentui/react";
import { useState, useEffect } from "react";
import AgentDisplay from "./src/tui/components/agent-display";
import type { Message, ToolMessage } from "./src/core/messages";
import type { Subagent } from "./src/tui/components/hooks/pentestAgent";

/**
 * Test file for AgentDisplay component - Version 2
 * Focuses on many long subagents with lots of messages
 * Run with: bun run test-agent-display-v2.tsx
 */

// Helper to generate realistic tool call sequences
// NOTE: This simulates the behavior where tool messages are UPDATED in place
// We still create them as separate messages for the initial data structure,
// but the streaming simulation will update them properly
function generateToolCalls(
  baseTime: number,
  startOffset: number,
  toolConfigs: Array<{
    name: string;
    description: string;
    args: any;
    duration: number;
  }>
): { pendingMessages: Message[]; completedMessages: Message[] } {
  const pendingMessages: Message[] = [];
  const completedMessages: Message[] = [];
  let currentOffset = startOffset;

  toolConfigs.forEach((tool, idx) => {
    const toolCallId = `tool-${baseTime}-${idx}`;

    // Pending tool call - added first
    pendingMessages.push({
      role: "tool",
      status: "pending",
      toolCallId,
      content: tool.description,
      args: tool.args,
      toolName: tool.name,
      createdAt: new Date(baseTime + currentOffset),
    });

    currentOffset += tool.duration;

    // Completed version - will replace the pending one
    completedMessages.push({
      role: "tool",
      status: "completed",
      toolCallId,
      content: `✓ ${tool.description}`,
      args: tool.args,
      toolName: tool.name,
      createdAt: new Date(baseTime + currentOffset),
    });

    currentOffset += 500;
  });

  return { pendingMessages, completedMessages };
}

// Generate main messages with lots of tool calls
function generateTestMessages(): Message[] {
  const messages: Message[] = [];
  const baseTime = new Date("2025-10-18T10:00:00Z").getTime();

  messages.push({
    role: "user",
    content:
      "Perform comprehensive security assessment of example.com with full vulnerability scanning",
    createdAt: new Date(baseTime),
  });

  messages.push({
    role: "assistant",
    content:
      "Starting comprehensive security assessment. I'll first perform initial reconnaissance before spawning specialized subagents...",
    createdAt: new Date(baseTime + 1000),
  });

  // Add many tool calls in main thread to simulate busy activity
  const mainTools = [
    { name: "whois", desc: "Looking up domain registration", duration: 2000 },
    { name: "dns_enum", desc: "Enumerating DNS records", duration: 3000 },
    { name: "ip_lookup", desc: "Resolving IP addresses", duration: 2000 },
    { name: "geo_location", desc: "Checking geolocation", duration: 1500 },
    { name: "asn_lookup", desc: "Looking up ASN information", duration: 2000 },
    { name: "reverse_dns", desc: "Performing reverse DNS", duration: 2500 },
    { name: "network_scan", desc: "Scanning network blocks", duration: 4000 },
    { name: "cert_check", desc: "Checking SSL certificates", duration: 3000 },
    { name: "cdn_detect", desc: "Detecting CDN usage", duration: 2000 },
    { name: "waf_detect", desc: "Detecting WAF presence", duration: 2500 },
  ];

  let offset = 2000;
  mainTools.forEach((tool, idx) => {
    const toolCallId = `main-tool-${idx}`;

    messages.push({
      role: "tool",
      status: "pending",
      toolCallId,
      content: tool.desc,
      args: { target: "example.com" },
      toolName: tool.name,
      createdAt: new Date(baseTime + offset),
    });

    offset += tool.duration;

    messages.push({
      role: "tool",
      status: "completed",
      toolCallId,
      content: `✓ ${tool.desc}`,
      args: { target: "example.com" },
      toolName: tool.name,
      createdAt: new Date(baseTime + offset),
    });

    offset += 500;

    // Add commentary after some tools
    if (idx === 3 || idx === 7) {
      messages.push({
        role: "assistant",
        content: `Initial reconnaissance progressing... ${idx + 1}/${
          mainTools.length
        } checks complete. Gathering more intelligence...`,
        createdAt: new Date(baseTime + offset),
      });
      offset += 1000;
    }
  });

  messages.push({
    role: "assistant",
    content:
      "Initial reconnaissance complete. Now spawning 16 specialized subagents to perform detailed security testing across all attack vectors...",
    createdAt: new Date(baseTime + offset),
  });

  return messages;
}

// Generate 16 comprehensive subagents with lots of messages
function generateTestSubagents(): Subagent[] {
  const baseTime = new Date("2025-10-18T10:05:00Z").getTime();
  const subagents: Subagent[] = [];

  const subagentConfigs = [
    {
      id: "subagent-1",
      name: "Attack Surface Enumeration",
      type: "attack-surface" as const,
      toolSequences: [
        [
          {
            name: "subdomain_enum",
            description: "Enumerating subdomains via DNS",
            args: { domain: "example.com" },
            duration: 3000,
          },
          {
            name: "ct_logs",
            description: "Checking certificate transparency",
            args: { domain: "example.com" },
            duration: 4000,
          },
          {
            name: "dns_resolve",
            description: "Resolving DNS records",
            args: { count: 15 },
            duration: 3000,
          },
          {
            name: "mx_lookup",
            description: "Checking mail server records",
            args: { domain: "example.com" },
            duration: 2000,
          },
          {
            name: "spf_check",
            description: "Analyzing SPF configuration",
            args: { domain: "example.com" },
            duration: 2000,
          },
          {
            name: "dmarc_check",
            description: "Analyzing DMARC policy",
            args: { domain: "example.com" },
            duration: 2000,
          },
          {
            name: "exposed_db_scan",
            description: "Scanning for exposed databases",
            args: { types: ["mongo", "redis"] },
            duration: 5000,
          },
          {
            name: "cloud_storage",
            description: "Checking cloud storage buckets",
            args: { provider: "aws" },
            duration: 3000,
          },
        ],
      ],
    },
    {
      id: "subagent-2",
      name: "Port & Service Discovery",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "quick_scan",
            description: "Quick port scan (top 1000)",
            args: { ports: 1000 },
            duration: 4000,
          },
          {
            name: "service_detect",
            description: "Detecting service versions",
            args: { ports: [22, 80, 443] },
            duration: 3000,
          },
          {
            name: "full_scan",
            description: "Full port range scan",
            args: { range: "1-65535" },
            duration: 15000,
          },
          {
            name: "os_detect",
            description: "Operating system fingerprinting",
            args: { target: "example.com" },
            duration: 4000,
          },
          {
            name: "cve_scan",
            description: "Scanning for known CVEs",
            args: { services: 6 },
            duration: 5000,
          },
          {
            name: "vuln_scripts",
            description: "Running vulnerability scripts",
            args: { count: 25 },
            duration: 8000,
          },
        ],
      ],
    },
    {
      id: "subagent-3",
      name: "Web Application Testing",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "spider",
            description: "Crawling web application",
            args: { depth: 5 },
            duration: 10000,
          },
          {
            name: "tech_detect",
            description: "Detecting technologies",
            args: { url: "https://example.com" },
            duration: 3000,
          },
          {
            name: "form_discovery",
            description: "Discovering forms",
            args: { pages: 127 },
            duration: 4000,
          },
          {
            name: "input_points",
            description: "Mapping input points",
            args: { count: 89 },
            duration: 3000,
          },
          {
            name: "js_analysis",
            description: "Analyzing JavaScript files",
            args: { files: 23 },
            duration: 6000,
          },
          {
            name: "api_discovery",
            description: "Discovering API endpoints",
            args: { method: "passive" },
            duration: 5000,
          },
          {
            name: "hidden_params",
            description: "Finding hidden parameters",
            args: { technique: "arjun" },
            duration: 4000,
          },
        ],
      ],
    },
    {
      id: "subagent-4",
      name: "SQL Injection Testing",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "sqli_login",
            description: "Testing login form",
            args: { endpoint: "/login" },
            duration: 5000,
          },
          {
            name: "sqli_search",
            description: "Testing search functionality",
            args: { endpoint: "/search" },
            duration: 4000,
          },
          {
            name: "sqli_params",
            description: "Testing GET parameters",
            args: { params: 45 },
            duration: 8000,
          },
          {
            name: "sqli_headers",
            description: "Testing HTTP headers",
            args: { headers: ["User-Agent", "Referer"] },
            duration: 3000,
          },
          {
            name: "sqli_cookies",
            description: "Testing cookie values",
            args: { cookies: 8 },
            duration: 3000,
          },
          {
            name: "sqli_blind",
            description: "Testing for blind SQL injection",
            args: { technique: "time-based" },
            duration: 12000,
          },
          {
            name: "sqli_union",
            description: "Testing UNION-based injection",
            args: { columns: 7 },
            duration: 6000,
          },
        ],
      ],
    },
    {
      id: "subagent-5",
      name: "XSS Vulnerability Assessment",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "xss_reflected",
            description: "Testing reflected XSS",
            args: { inputs: 89 },
            duration: 10000,
          },
          {
            name: "xss_stored",
            description: "Testing stored XSS",
            args: { forms: 15 },
            duration: 8000,
          },
          {
            name: "xss_dom",
            description: "Testing DOM-based XSS",
            args: { js_sinks: 34 },
            duration: 7000,
          },
          {
            name: "xss_bypass",
            description: "Testing filter bypasses",
            args: { filters: ["htmlspecialchars"] },
            duration: 6000,
          },
          {
            name: "xss_polyglot",
            description: "Testing polyglot payloads",
            args: { contexts: 12 },
            duration: 5000,
          },
        ],
      ],
    },
    {
      id: "subagent-6",
      name: "Authentication & Session Testing",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "auth_brute",
            description: "Testing account lockout",
            args: { attempts: 20 },
            duration: 6000,
          },
          {
            name: "session_fixation",
            description: "Testing session fixation",
            args: { target: "example.com" },
            duration: 4000,
          },
          {
            name: "session_timeout",
            description: "Testing session timeout",
            args: { idle_time: 1800 },
            duration: 5000,
          },
          {
            name: "cookie_security",
            description: "Analyzing cookie security",
            args: { flags: ["Secure", "HttpOnly"] },
            duration: 3000,
          },
          {
            name: "jwt_security",
            description: "Testing JWT implementation",
            args: { algorithm: "RS256" },
            duration: 4000,
          },
          {
            name: "oauth_flows",
            description: "Testing OAuth flows",
            args: { providers: 3 },
            duration: 6000,
          },
          {
            name: "mfa_bypass",
            description: "Testing MFA implementation",
            args: { methods: 2 },
            duration: 5000,
          },
        ],
      ],
    },
    {
      id: "subagent-7",
      name: "Authorization & Access Control",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "idor_test",
            description: "Testing for IDOR",
            args: { endpoints: 45 },
            duration: 8000,
          },
          {
            name: "priv_esc",
            description: "Testing privilege escalation",
            args: { roles: ["user", "admin"] },
            duration: 6000,
          },
          {
            name: "path_traversal",
            description: "Testing path traversal",
            args: { params: 23 },
            duration: 5000,
          },
          {
            name: "forced_browsing",
            description: "Testing forced browsing",
            args: { paths: 78 },
            duration: 7000,
          },
          {
            name: "api_authz",
            description: "Testing API authorization",
            args: { endpoints: 34 },
            duration: 6000,
          },
        ],
      ],
    },
    {
      id: "subagent-8",
      name: "CSRF & SSRF Testing",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "csrf_tokens",
            description: "Testing CSRF tokens",
            args: { forms: 18 },
            duration: 5000,
          },
          {
            name: "csrf_samesite",
            description: "Testing SameSite cookies",
            args: { cookies: 12 },
            duration: 3000,
          },
          {
            name: "ssrf_urls",
            description: "Testing SSRF in URL parameters",
            args: { params: 15 },
            duration: 6000,
          },
          {
            name: "ssrf_upload",
            description: "Testing SSRF via file upload",
            args: { endpoints: 3 },
            duration: 5000,
          },
          {
            name: "ssrf_webhooks",
            description: "Testing SSRF in webhooks",
            args: { callbacks: 5 },
            duration: 4000,
          },
        ],
      ],
    },
    {
      id: "subagent-9",
      name: "File Upload Security",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "upload_types",
            description: "Testing file type restrictions",
            args: { extensions: 20 },
            duration: 6000,
          },
          {
            name: "upload_magic",
            description: "Testing magic byte validation",
            args: { files: 15 },
            duration: 5000,
          },
          {
            name: "upload_size",
            description: "Testing file size limits",
            args: { max_size: "10MB" },
            duration: 3000,
          },
          {
            name: "upload_rce",
            description: "Testing for RCE via upload",
            args: { payloads: 8 },
            duration: 7000,
          },
          {
            name: "upload_path",
            description: "Testing path traversal in uploads",
            args: { techniques: 5 },
            duration: 4000,
          },
          {
            name: "upload_xxe",
            description: "Testing XXE via file upload",
            args: { formats: ["xml", "svg"] },
            duration: 5000,
          },
        ],
      ],
    },
    {
      id: "subagent-10",
      name: "API Security Assessment",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "api_discovery",
            description: "Discovering API endpoints",
            args: { methods: ["GET", "POST"] },
            duration: 5000,
          },
          {
            name: "api_auth",
            description: "Testing API authentication",
            args: { schemes: ["Bearer", "Basic"] },
            duration: 4000,
          },
          {
            name: "api_rate_limit",
            description: "Testing rate limiting",
            args: { requests: 1000 },
            duration: 8000,
          },
          {
            name: "api_versioning",
            description: "Testing API versioning",
            args: { versions: [1, 2, 3] },
            duration: 3000,
          },
          {
            name: "api_injection",
            description: "Testing injection vectors",
            args: { types: ["SQL", "NoSQL", "LDAP"] },
            duration: 9000,
          },
          {
            name: "api_schema",
            description: "Analyzing API schema",
            args: { format: "OpenAPI" },
            duration: 4000,
          },
        ],
      ],
    },
    {
      id: "subagent-11",
      name: "SSL/TLS Configuration",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "ssl_protocols",
            description: "Testing SSL/TLS protocols",
            args: { target: "example.com" },
            duration: 5000,
          },
          {
            name: "ssl_ciphers",
            description: "Testing cipher suites",
            args: { strong_only: true },
            duration: 4000,
          },
          {
            name: "ssl_cert",
            description: "Analyzing certificate",
            args: { chain: true },
            duration: 3000,
          },
          {
            name: "ssl_hsts",
            description: "Testing HSTS implementation",
            args: { preload: true },
            duration: 2000,
          },
          {
            name: "ssl_vulnerabilities",
            description: "Testing for SSL vulnerabilities",
            args: { tests: ["BEAST", "CRIME", "Heartbleed"] },
            duration: 6000,
          },
        ],
      ],
    },
    {
      id: "subagent-12",
      name: "Security Headers Analysis",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "csp_analysis",
            description: "Analyzing Content-Security-Policy",
            args: { directives: 15 },
            duration: 4000,
          },
          {
            name: "cors_analysis",
            description: "Testing CORS configuration",
            args: { origins: "*" },
            duration: 3000,
          },
          {
            name: "header_security",
            description: "Checking security headers",
            args: { headers: ["X-Frame-Options", "X-XSS-Protection"] },
            duration: 3000,
          },
          {
            name: "cache_headers",
            description: "Analyzing cache headers",
            args: { sensitive: true },
            duration: 2000,
          },
          {
            name: "info_disclosure",
            description: "Testing information disclosure",
            args: { headers: ["Server", "X-Powered-By"] },
            duration: 3000,
          },
        ],
      ],
    },
    {
      id: "subagent-13",
      name: "Business Logic Testing",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "workflow_test",
            description: "Testing payment workflow",
            args: { steps: 8 },
            duration: 6000,
          },
          {
            name: "race_condition",
            description: "Testing for race conditions",
            args: { endpoint: "/checkout" },
            duration: 5000,
          },
          {
            name: "price_manipulation",
            description: "Testing price manipulation",
            args: { items: 12 },
            duration: 5000,
          },
          {
            name: "quantity_bypass",
            description: "Testing quantity restrictions",
            args: { limits: [1, 10, 100] },
            duration: 4000,
          },
          {
            name: "coupon_abuse",
            description: "Testing coupon code abuse",
            args: { codes: 5 },
            duration: 4000,
          },
          {
            name: "refund_logic",
            description: "Testing refund logic",
            args: { scenarios: 8 },
            duration: 5000,
          },
        ],
      ],
    },
    {
      id: "subagent-14",
      name: "Cryptographic Analysis",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "password_storage",
            description: "Analyzing password storage",
            args: { algorithm: "bcrypt" },
            duration: 4000,
          },
          {
            name: "encryption_at_rest",
            description: "Testing data encryption",
            args: { databases: 3 },
            duration: 5000,
          },
          {
            name: "encryption_transit",
            description: "Testing encryption in transit",
            args: { protocols: ["TLS 1.2", "TLS 1.3"] },
            duration: 4000,
          },
          {
            name: "key_management",
            description: "Analyzing key management",
            args: { rotation: true },
            duration: 3000,
          },
          {
            name: "random_generation",
            description: "Testing random number generation",
            args: { samples: 1000 },
            duration: 6000,
          },
        ],
      ],
    },
    {
      id: "subagent-15",
      name: "Third-Party Integration Security",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "dependency_scan",
            description: "Scanning dependencies",
            args: { packages: 234 },
            duration: 8000,
          },
          {
            name: "cve_check",
            description: "Checking for known CVEs",
            args: { severity: "high" },
            duration: 6000,
          },
          {
            name: "supply_chain",
            description: "Analyzing supply chain risks",
            args: { depth: 3 },
            duration: 5000,
          },
          {
            name: "api_integrations",
            description: "Testing third-party APIs",
            args: { services: ["payment", "auth", "email"] },
            duration: 7000,
          },
          {
            name: "cdn_security",
            description: "Analyzing CDN configuration",
            args: { providers: 2 },
            duration: 4000,
          },
        ],
      ],
    },
    {
      id: "subagent-16",
      name: "Compliance & Best Practices",
      type: "pentest" as const,
      toolSequences: [
        [
          {
            name: "owasp_top10",
            description: "Checking OWASP Top 10",
            args: { year: 2021 },
            duration: 5000,
          },
          {
            name: "pci_dss",
            description: "Testing PCI DSS compliance",
            args: { requirements: 12 },
            duration: 6000,
          },
          {
            name: "gdpr_check",
            description: "Checking GDPR compliance",
            args: { data_types: ["PII", "sensitive"] },
            duration: 4000,
          },
          {
            name: "logging_monitoring",
            description: "Testing logging practices",
            args: { events: 45 },
            duration: 4000,
          },
          {
            name: "incident_response",
            description: "Reviewing incident response",
            args: { procedures: true },
            duration: 3000,
          },
          {
            name: "backup_recovery",
            description: "Testing backup procedures",
            args: { frequency: "daily" },
            duration: 4000,
          },
        ],
      ],
    },
  ];

  subagentConfigs.forEach((config, idx) => {
    const subagentStartTime = baseTime + idx * 10000;
    const messages: Message[] = [];

    // Initial message
    messages.push({
      role: "assistant",
      content: `Starting ${config.name.toLowerCase()}. This will perform comprehensive testing across multiple attack vectors...`,
      createdAt: new Date(subagentStartTime),
    });

    let offset = 1000;

    // Process each tool sequence (repeat 3x to make it MUCH longer)
    for (let repeat = 0; repeat < 3; repeat++) {
      config.toolSequences.forEach((toolSeq, seqIdx) => {
        // Generate tool calls - only use completed ones to simulate they replaced pending
        const { completedMessages } = generateToolCalls(
          subagentStartTime,
          offset,
          toolSeq
        );
        messages.push(...completedMessages);

        offset +=
          toolSeq.reduce((sum, tool) => sum + tool.duration + 500, 0) + 1000;

        // Add analysis message between sequences
        messages.push({
          role: "assistant",
          content: `Phase ${repeat + 1}: Completed ${
            toolSeq.length
          } tests in this round. ${
            repeat < 2
              ? "Continuing with more comprehensive testing..."
              : "Preparing final analysis..."
          }`,
          createdAt: new Date(subagentStartTime + offset),
        });

        offset += 1000;
      });
    }

    // Final summary
    messages.push({
      role: "assistant",
      content: `${config.name} complete.\n\n**Summary:**\n- Tests performed: ${
        config.toolSequences.flat().length
      }\n- Vulnerabilities found: ${Math.floor(
        Math.random() * 3
      )}\n- Severity: ${
        ["Low", "Medium", "High"][Math.floor(Math.random() * 3)]
      }\n- Recommendations: ${Math.floor(Math.random() * 5) + 2}`,
      createdAt: new Date(subagentStartTime + offset),
    });

    subagents.push({
      id: config.id,
      name: config.name,
      type: config.type,
      target: "example.com",
      status: idx < 15 ? "completed" : "pending",
      createdAt: new Date(subagentStartTime),
      messages,
    });
  });

  return subagents;
}

function App() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [subagents, setSubagents] = useState<Subagent[]>([]);
  const [isStreaming, setIsStreaming] = useState(true);
  const [messageIndex, setMessageIndex] = useState(0);
  const [subagentIndex, setSubagentIndex] = useState(0);

  const allMessages = generateTestMessages();
  const allSubagents = generateTestSubagents();

  // Simulate streaming
  useEffect(() => {
    if (messageIndex < allMessages.length) {
      const timer = setTimeout(() => {
        setMessages(allMessages.slice(0, messageIndex + 1));
        setMessageIndex(messageIndex + 1);
      }, 50);
      return () => clearTimeout(timer);
    } else if (subagentIndex < allSubagents.length) {
      const timer = setTimeout(() => {
        const newSubagents = allSubagents.slice(0, subagentIndex + 1);
        const latestSubagent = newSubagents[newSubagents.length - 1];
        if (latestSubagent) {
          console.log(
            `Adding subagent ${subagentIndex + 1}/16: ${latestSubagent.name}`
          );
        }
        setSubagents(newSubagents);
        setSubagentIndex(subagentIndex + 1);
      }, 200); // Faster to load them all quickly
      return () => clearTimeout(timer);
    } else {
      setIsStreaming(false);
      console.log("All subagents loaded. Total:", allSubagents.length);
      console.log(
        "Subagent message counts:",
        allSubagents.map((s) => ({
          name: s.name,
          messageCount: s.messages.length,
          toolCalls: s.messages.filter((m) => m.role === "tool").length,
        }))
      );
    }
  }, [messageIndex, subagentIndex]);

  // Log when render happens
  console.log(
    `Rendering: ${messages.length} messages, ${subagents.length} subagents`
  );

  const totalToolCalls = messages.filter((m) => m.role === "tool").length;
  const subagentToolCalls = subagents.reduce(
    (sum, s) => sum + s.messages.filter((m) => m.role === "tool").length,
    0
  );

  console.log(
    `Tool calls - Main: ${totalToolCalls}, Subagents: ${subagentToolCalls}, Total: ${
      totalToolCalls + subagentToolCalls
    }`
  );

  return (
    <box flexDirection="column" width="100%" height="100%">
      {/* Agent display */}
      <AgentDisplay
        messages={messages}
        subagents={subagents}
        isStreaming={isStreaming}
      />
    </box>
  );
}

render(<App />, {
  exitOnCtrlC: true,
});
