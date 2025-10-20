#!/usr/bin/env bun
import { render } from "@opentui/react";
import { useState, useEffect } from "react";
import AgentDisplay from "./src/tui/components/agent-display";
import type { Message, ToolMessage } from "./src/core/messages";
import type { Subagent } from "./src/tui/components/hooks/pentestAgent";

/**
 * Test file for AgentDisplay component
 * This simulates streaming messages and tool calls to diagnose the issue
 * where tool calls disappear when enough messages appear.
 *
 * Run with: bun run test-agent-display.tsx
 */

// Generate a large set of test messages with tool calls
function generateTestMessages(): Message[] {
  const messages: Message[] = [];
  const baseTime = new Date("2025-10-18T10:00:00Z");

  // Initial user message
  messages.push({
    role: "user",
    content: "Test objective: Analyze the security of example.com",
    createdAt: new Date(baseTime.getTime()),
  });

  // Simulate multiple rounds of assistant responses with tool calls
  for (let round = 0; round < 8; round++) {
    const roundTime = baseTime.getTime() + round * 60000; // 1 minute apart

    // Add occasional user messages
    if (round === 2) {
      messages.push({
        role: "user",
        content:
          "Can you focus on checking for authentication vulnerabilities?",
        createdAt: new Date(roundTime - 500),
      });
    } else if (round === 5) {
      messages.push({
        role: "user",
        content: "Also check the API endpoints for any security issues.",
        createdAt: new Date(roundTime - 500),
      });
    }

    // Assistant thinking message
    messages.push({
      role: "assistant",
      content: `Round ${
        round + 1
      }: Analyzing the target and planning next steps. Let me gather some information about the domain configuration and potential vulnerabilities.`,
      createdAt: new Date(roundTime + 1000),
    });

    // Multiple tool calls in this round
    const toolCalls = [
      {
        name: "dns_lookup",
        description: "Looking up DNS records",
        args: { domain: "example.com", record_type: "A" },
      },
      {
        name: "port_scan",
        description: "Scanning common ports",
        args: { host: "example.com", ports: [80, 443, 8080, 8443] },
      },
      {
        name: "http_headers",
        description: "Analyzing HTTP headers",
        args: { url: "https://example.com" },
      },
      {
        name: "ssl_certificate",
        description: "Checking SSL certificate",
        args: { domain: "example.com" },
      },
    ];

    toolCalls.forEach((tool, idx) => {
      const toolCallId = `tool-${round}-${idx}`;

      // Pending tool call
      messages.push({
        role: "tool",
        status: "pending",
        toolCallId,
        content: tool.description,
        args: tool.args,
        toolName: tool.name,
        createdAt: new Date(roundTime + 2000 + idx * 500),
      });

      // Completed tool call (simulating result coming back)
      messages.push({
        role: "tool",
        status: "completed",
        toolCallId,
        content: `✓ ${tool.description}`,
        args: tool.args,
        toolName: tool.name,
        createdAt: new Date(roundTime + 4000 + idx * 500),
      });
    });

    // Assistant analysis after tool calls
    messages.push({
      role: "assistant",
      content: `Based on the tool results from round ${
        round + 1
      }:\n\n**Findings:**\n- DNS records retrieved successfully\n- Open ports detected: 80, 443\n- HTTP headers indicate Apache web server\n- SSL certificate is valid\n\nLet me continue with deeper analysis...`,
      createdAt: new Date(roundTime + 8000),
    });
  }

  // Final summary
  messages.push({
    role: "assistant",
    content: `## Summary\n\nCompleted comprehensive security analysis with ${
      messages.filter((m) => m.role === "tool").length / 2
    } tool calls across 8 rounds.\n\n**Key Findings:**\n- Target is responding on standard ports\n- SSL configuration appears secure\n- No immediate critical vulnerabilities detected\n\nRecommend further manual testing for application-level vulnerabilities.`,
    createdAt: new Date(baseTime.getTime() + 480000),
  });

  return messages;
}

// Generate test subagents
function generateTestSubagents(): Subagent[] {
  const baseTime = new Date("2025-10-18T10:05:00Z");

  const subagents: Subagent[] = [
    {
      id: "subagent-1",
      name: "Attack Surface Analysis",
      type: "attack-surface",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime()),
      messages: [
        {
          role: "assistant",
          content: "Starting comprehensive attack surface analysis...",
          createdAt: new Date(baseTime.getTime() + 1000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-1-1",
          content: "Enumerating subdomains via DNS",
          args: { domain: "example.com", method: "dns" },
          toolName: "subdomain_enum",
          createdAt: new Date(baseTime.getTime() + 2000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-1-1",
          content: "✓ Enumerating subdomains via DNS",
          args: { domain: "example.com", method: "dns" },
          toolName: "subdomain_enum",
          createdAt: new Date(baseTime.getTime() + 5000),
        },
        {
          role: "assistant",
          content:
            "Found 12 subdomains via DNS. Let me try certificate transparency logs for more...",
          createdAt: new Date(baseTime.getTime() + 6000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-1-2",
          content: "Checking certificate transparency logs",
          args: { domain: "example.com" },
          toolName: "ct_logs_check",
          createdAt: new Date(baseTime.getTime() + 7000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-1-2",
          content: "✓ Checking certificate transparency logs",
          args: { domain: "example.com" },
          toolName: "ct_logs_check",
          createdAt: new Date(baseTime.getTime() + 10000),
        },
        {
          role: "assistant",
          content:
            "Found additional subdomains:\n- www.example.com\n- mail.example.com\n- api.example.com\n- dev.example.com\n- staging.example.com\n- admin.example.com\n- cdn.example.com\n- blog.example.com\n\nNow checking DNS records for each...",
          createdAt: new Date(baseTime.getTime() + 11000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-1-3",
          content: "Resolving A records",
          args: { subdomains: 8 },
          toolName: "dns_resolve",
          createdAt: new Date(baseTime.getTime() + 12000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-1-3",
          content: "✓ Resolving A records",
          args: { subdomains: 8 },
          toolName: "dns_resolve",
          createdAt: new Date(baseTime.getTime() + 15000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-1-4",
          content: "Checking MX records",
          args: { domain: "example.com" },
          toolName: "mx_lookup",
          createdAt: new Date(baseTime.getTime() + 16000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-1-4",
          content: "✓ Checking MX records",
          args: { domain: "example.com" },
          toolName: "mx_lookup",
          createdAt: new Date(baseTime.getTime() + 18000),
        },
        {
          role: "assistant",
          content:
            "Mail servers identified. Checking SPF and DMARC policies...",
          createdAt: new Date(baseTime.getTime() + 19000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-1-5",
          content: "Analyzing SPF records",
          args: { domain: "example.com" },
          toolName: "spf_check",
          createdAt: new Date(baseTime.getTime() + 20000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-1-5",
          content: "✓ Analyzing SPF records",
          args: { domain: "example.com" },
          toolName: "spf_check",
          createdAt: new Date(baseTime.getTime() + 22000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-1-6",
          content: "Analyzing DMARC policy",
          args: { domain: "example.com" },
          toolName: "dmarc_check",
          createdAt: new Date(baseTime.getTime() + 23000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-1-6",
          content: "✓ Analyzing DMARC policy",
          args: { domain: "example.com" },
          toolName: "dmarc_check",
          createdAt: new Date(baseTime.getTime() + 25000),
        },
        {
          role: "assistant",
          content:
            "Email security configuration:\n- SPF: Configured with -all\n- DMARC: Quarantine policy active\n- DKIM: Present on mail servers\n\nNow checking for exposed services...",
          createdAt: new Date(baseTime.getTime() + 26000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-1-7",
          content: "Scanning for exposed databases",
          args: { targets: ["mongodb", "redis", "elasticsearch"] },
          toolName: "service_scan",
          createdAt: new Date(baseTime.getTime() + 27000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-1-7",
          content: "✓ Scanning for exposed databases",
          args: { targets: ["mongodb", "redis", "elasticsearch"] },
          toolName: "service_scan",
          createdAt: new Date(baseTime.getTime() + 32000),
        },
        {
          role: "assistant",
          content:
            "No exposed databases found. Checking cloud storage buckets...",
          createdAt: new Date(baseTime.getTime() + 33000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-1-8",
          content: "Checking S3 buckets",
          args: { domain: "example.com" },
          toolName: "s3_enum",
          createdAt: new Date(baseTime.getTime() + 34000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-1-8",
          content: "✓ Checking S3 buckets",
          args: { domain: "example.com" },
          toolName: "s3_enum",
          createdAt: new Date(baseTime.getTime() + 37000),
        },
        {
          role: "assistant",
          content:
            "Attack surface analysis complete.\n\n**Summary:**\n- 8 active subdomains identified\n- Mail servers properly configured\n- No exposed databases\n- Cloud storage properly secured\n- Total attack surface: Medium",
          createdAt: new Date(baseTime.getTime() + 38000),
        },
      ],
    },
    {
      id: "subagent-2",
      name: "Deep Port Scan",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 12000),
      messages: [
        {
          role: "assistant",
          content:
            "Performing comprehensive port scan with service detection...",
          createdAt: new Date(baseTime.getTime() + 13000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-2-1",
          content: "Scanning top 100 most common ports",
          args: { host: "example.com", top_ports: 100 },
          toolName: "nmap_scan",
          createdAt: new Date(baseTime.getTime() + 14000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-2-1",
          content: "✓ Scanning top 100 most common ports",
          args: { host: "example.com", top_ports: 100 },
          toolName: "nmap_scan",
          createdAt: new Date(baseTime.getTime() + 20000),
        },
        {
          role: "assistant",
          content:
            "Found 6 open ports in top 100. Performing service version detection...",
          createdAt: new Date(baseTime.getTime() + 21000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-2-2",
          content: "Detecting service versions",
          args: { ports: [22, 80, 443, 3306, 8080, 9090] },
          toolName: "service_detection",
          createdAt: new Date(baseTime.getTime() + 22000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-2-2",
          content: "✓ Detecting service versions",
          args: { ports: [22, 80, 443, 3306, 8080, 9090] },
          toolName: "service_detection",
          createdAt: new Date(baseTime.getTime() + 28000),
        },
        {
          role: "assistant",
          content:
            "Services identified:\n- Port 22: OpenSSH 8.2p1\n- Port 80: nginx 1.18.0\n- Port 443: nginx 1.18.0 (TLS)\n- Port 3306: MySQL 8.0.25\n- Port 8080: Apache Tomcat 9.0\n- Port 9090: Prometheus\n\nScanning full port range...",
          createdAt: new Date(baseTime.getTime() + 29000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-2-3",
          content: "Scanning all 65535 ports",
          args: { host: "example.com", range: "1-65535" },
          toolName: "full_port_scan",
          createdAt: new Date(baseTime.getTime() + 30000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-2-3",
          content: "✓ Scanning all 65535 ports",
          args: { host: "example.com", range: "1-65535" },
          toolName: "full_port_scan",
          createdAt: new Date(baseTime.getTime() + 50000),
        },
        {
          role: "assistant",
          content:
            "Full scan complete. No additional ports found. Running OS detection...",
          createdAt: new Date(baseTime.getTime() + 51000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-2-4",
          content: "Detecting operating system",
          args: { host: "example.com" },
          toolName: "os_detection",
          createdAt: new Date(baseTime.getTime() + 52000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-2-4",
          content: "✓ Detecting operating system",
          args: { host: "example.com" },
          toolName: "os_detection",
          createdAt: new Date(baseTime.getTime() + 56000),
        },
        {
          role: "assistant",
          content:
            "OS Detection: Linux 5.4 (Ubuntu 20.04)\n\nChecking for known vulnerabilities in detected services...",
          createdAt: new Date(baseTime.getTime() + 57000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-2-5",
          content: "Running CVE scan on services",
          args: { services: ["OpenSSH 8.2p1", "nginx 1.18.0", "MySQL 8.0.25"] },
          toolName: "cve_scan",
          createdAt: new Date(baseTime.getTime() + 58000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-2-5",
          content: "✓ Running CVE scan on services",
          args: { services: ["OpenSSH 8.2p1", "nginx 1.18.0", "MySQL 8.0.25"] },
          toolName: "cve_scan",
          createdAt: new Date(baseTime.getTime() + 63000),
        },
        {
          role: "assistant",
          content:
            "Port scan analysis complete.\n\n**Open Ports:**\n- 22 (SSH) - OpenSSH 8.2p1 - No CVEs\n- 80 (HTTP) - nginx 1.18.0 - No CVEs\n- 443 (HTTPS) - nginx 1.18.0 - No CVEs\n- 3306 (MySQL) - Version 8.0.25 - No CVEs\n- 8080 (Tomcat) - Version 9.0 - Minor CVEs\n- 9090 (Prometheus) - Unauthenticated access\n\n**Concerns:**\n- MySQL port 3306 should not be publicly accessible\n- Prometheus port 9090 lacks authentication",
          createdAt: new Date(baseTime.getTime() + 64000),
        },
      ],
    },
    {
      id: "subagent-3",
      name: "Web Application Analysis",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 45000),
      messages: [
        {
          role: "assistant",
          content: "Analyzing web application structure...",
          createdAt: new Date(baseTime.getTime() + 46000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-3-1",
          content: "Crawling web application",
          args: { url: "https://example.com", depth: 3 },
          toolName: "web_crawler",
          createdAt: new Date(baseTime.getTime() + 47000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-3-1",
          content: "✓ Crawling web application",
          args: { url: "https://example.com", depth: 3 },
          toolName: "web_crawler",
          createdAt: new Date(baseTime.getTime() + 55000),
        },
        {
          role: "assistant",
          content: "Found 127 pages. Analyzing for vulnerabilities...",
          createdAt: new Date(baseTime.getTime() + 56000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-3-2",
          content: "Scanning for XSS vulnerabilities",
          args: { pages: 127 },
          toolName: "xss_scanner",
          createdAt: new Date(baseTime.getTime() + 57000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-3-2",
          content: "✓ Scanning for XSS vulnerabilities",
          args: { pages: 127 },
          toolName: "xss_scanner",
          createdAt: new Date(baseTime.getTime() + 65000),
        },
        {
          role: "assistant",
          content: "No XSS vulnerabilities detected. Web app appears secure.",
          createdAt: new Date(baseTime.getTime() + 66000),
        },
      ],
    },
    {
      id: "subagent-4",
      name: "SQL Injection Testing",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 70000),
      messages: [
        {
          role: "assistant",
          content: "Testing for SQL injection vulnerabilities...",
          createdAt: new Date(baseTime.getTime() + 71000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-4-1",
          content: "Testing login form",
          args: { endpoint: "/login", method: "POST" },
          toolName: "sqli_test",
          createdAt: new Date(baseTime.getTime() + 72000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-4-1",
          content: "✓ Testing login form",
          args: { endpoint: "/login", method: "POST" },
          toolName: "sqli_test",
          createdAt: new Date(baseTime.getTime() + 75000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-4-2",
          content: "Testing search functionality",
          args: { endpoint: "/search", method: "GET" },
          toolName: "sqli_test",
          createdAt: new Date(baseTime.getTime() + 76000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-4-2",
          content: "✓ Testing search functionality",
          args: { endpoint: "/search", method: "GET" },
          toolName: "sqli_test",
          createdAt: new Date(baseTime.getTime() + 79000),
        },
        {
          role: "assistant",
          content:
            "SQL injection testing complete. No vulnerabilities found. Parameterized queries appear to be in use.",
          createdAt: new Date(baseTime.getTime() + 80000),
        },
      ],
    },
    {
      id: "subagent-5",
      name: "API Security Assessment",
      type: "pentest",
      target: "api.example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 85000),
      messages: [
        {
          role: "assistant",
          content: "Assessing API security posture...",
          createdAt: new Date(baseTime.getTime() + 86000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-5-1",
          content: "Discovering API endpoints",
          args: { base_url: "https://api.example.com" },
          toolName: "api_discovery",
          createdAt: new Date(baseTime.getTime() + 87000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-5-1",
          content: "✓ Discovering API endpoints",
          args: { base_url: "https://api.example.com" },
          toolName: "api_discovery",
          createdAt: new Date(baseTime.getTime() + 92000),
        },
        {
          role: "assistant",
          content: "Found 23 API endpoints. Testing authentication...",
          createdAt: new Date(baseTime.getTime() + 93000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-5-2",
          content: "Testing authentication mechanisms",
          args: { endpoints: 23 },
          toolName: "auth_test",
          createdAt: new Date(baseTime.getTime() + 94000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-5-2",
          content: "✓ Testing authentication mechanisms",
          args: { endpoints: 23 },
          toolName: "auth_test",
          createdAt: new Date(baseTime.getTime() + 100000),
        },
        {
          role: "assistant",
          content:
            "API security assessment complete:\n- All endpoints require authentication\n- JWT tokens properly validated\n- Rate limiting implemented\n- No sensitive data exposure detected",
          createdAt: new Date(baseTime.getTime() + 101000),
        },
      ],
    },
    {
      id: "subagent-6",
      name: "SSL/TLS Configuration Review",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 105000),
      messages: [
        {
          role: "assistant",
          content: "Reviewing SSL/TLS configuration...",
          createdAt: new Date(baseTime.getTime() + 106000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-6-1",
          content: "Testing SSL protocols",
          args: { domain: "example.com" },
          toolName: "ssl_test",
          createdAt: new Date(baseTime.getTime() + 107000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-6-1",
          content: "✓ Testing SSL protocols",
          args: { domain: "example.com" },
          toolName: "ssl_test",
          createdAt: new Date(baseTime.getTime() + 112000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-6-2",
          content: "Checking cipher suites",
          args: { domain: "example.com" },
          toolName: "cipher_check",
          createdAt: new Date(baseTime.getTime() + 113000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-6-2",
          content: "✓ Checking cipher suites",
          args: { domain: "example.com" },
          toolName: "cipher_check",
          createdAt: new Date(baseTime.getTime() + 116000),
        },
        {
          role: "assistant",
          content:
            "SSL/TLS configuration review:\n- TLS 1.2 and 1.3 supported\n- TLS 1.0 and 1.1 disabled ✓\n- Strong cipher suites enabled\n- Certificate chain valid\n- HSTS header present",
          createdAt: new Date(baseTime.getTime() + 117000),
        },
      ],
    },
    {
      id: "subagent-7",
      name: "Authentication Bypass Testing",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 120000),
      messages: [
        {
          role: "assistant",
          content: "Testing for authentication bypass vulnerabilities...",
          createdAt: new Date(baseTime.getTime() + 121000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-7-1",
          content: "Testing direct object references",
          args: { endpoints: ["/user/profile", "/admin/dashboard"] },
          toolName: "idor_test",
          createdAt: new Date(baseTime.getTime() + 122000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-7-1",
          content: "✓ Testing direct object references",
          args: { endpoints: ["/user/profile", "/admin/dashboard"] },
          toolName: "idor_test",
          createdAt: new Date(baseTime.getTime() + 127000),
        },
        {
          role: "assistant",
          content:
            "No IDOR vulnerabilities detected. Authorization checks are properly implemented.",
          createdAt: new Date(baseTime.getTime() + 128000),
        },
      ],
    },
    {
      id: "subagent-8",
      name: "CSRF Token Validation",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 130000),
      messages: [
        {
          role: "assistant",
          content: "Testing CSRF protection mechanisms...",
          createdAt: new Date(baseTime.getTime() + 131000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-8-1",
          content: "Checking CSRF tokens on forms",
          args: { forms: ["/login", "/register", "/settings"] },
          toolName: "csrf_test",
          createdAt: new Date(baseTime.getTime() + 132000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-8-1",
          content: "✓ Checking CSRF tokens on forms",
          args: { forms: ["/login", "/register", "/settings"] },
          toolName: "csrf_test",
          createdAt: new Date(baseTime.getTime() + 137000),
        },
        {
          role: "assistant",
          content:
            "All forms properly implement CSRF protection. Tokens validated on server side.",
          createdAt: new Date(baseTime.getTime() + 138000),
        },
      ],
    },
    {
      id: "subagent-9",
      name: "File Upload Security",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 140000),
      messages: [
        {
          role: "assistant",
          content: "Analyzing file upload functionality for security issues...",
          createdAt: new Date(baseTime.getTime() + 141000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-9-1",
          content: "Testing file type validation",
          args: { endpoint: "/upload" },
          toolName: "file_upload_test",
          createdAt: new Date(baseTime.getTime() + 142000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-9-1",
          content: "✓ Testing file type validation",
          args: { endpoint: "/upload" },
          toolName: "file_upload_test",
          createdAt: new Date(baseTime.getTime() + 148000),
        },
        {
          role: "assistant",
          content:
            "File upload validation is secure:\n- File type restrictions enforced\n- Size limits in place\n- Content scanning implemented\n- Files stored outside web root",
          createdAt: new Date(baseTime.getTime() + 149000),
        },
      ],
    },
    {
      id: "subagent-10",
      name: "Session Management Review",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 150000),
      messages: [
        {
          role: "assistant",
          content: "Reviewing session management implementation...",
          createdAt: new Date(baseTime.getTime() + 151000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-10-1",
          content: "Testing session fixation",
          args: { target: "example.com" },
          toolName: "session_test",
          createdAt: new Date(baseTime.getTime() + 152000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-10-1",
          content: "✓ Testing session fixation",
          args: { target: "example.com" },
          toolName: "session_test",
          createdAt: new Date(baseTime.getTime() + 156000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-10-2",
          content: "Checking session timeout",
          args: { target: "example.com" },
          toolName: "timeout_test",
          createdAt: new Date(baseTime.getTime() + 157000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-10-2",
          content: "✓ Checking session timeout",
          args: { target: "example.com" },
          toolName: "timeout_test",
          createdAt: new Date(baseTime.getTime() + 160000),
        },
        {
          role: "assistant",
          content:
            "Session management is secure:\n- Session IDs regenerated after login\n- Appropriate timeout configured (30 min)\n- Secure and HttpOnly flags set on cookies",
          createdAt: new Date(baseTime.getTime() + 161000),
        },
      ],
    },
    {
      id: "subagent-11",
      name: "Directory Traversal Testing",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 165000),
      messages: [
        {
          role: "assistant",
          content: "Testing for directory traversal vulnerabilities...",
          createdAt: new Date(baseTime.getTime() + 166000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-11-1",
          content: "Testing path traversal in file parameters",
          args: { params: ["file", "path", "document"] },
          toolName: "path_traversal_test",
          createdAt: new Date(baseTime.getTime() + 167000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-11-1",
          content: "✓ Testing path traversal in file parameters",
          args: { params: ["file", "path", "document"] },
          toolName: "path_traversal_test",
          createdAt: new Date(baseTime.getTime() + 172000),
        },
        {
          role: "assistant",
          content:
            "No directory traversal vulnerabilities found. Path sanitization working correctly.",
          createdAt: new Date(baseTime.getTime() + 173000),
        },
      ],
    },
    {
      id: "subagent-12",
      name: "Information Disclosure Check",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 175000),
      messages: [
        {
          role: "assistant",
          content: "Checking for information disclosure vulnerabilities...",
          createdAt: new Date(baseTime.getTime() + 176000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-12-1",
          content: "Checking HTTP headers for info leakage",
          args: { url: "https://example.com" },
          toolName: "header_disclosure_test",
          createdAt: new Date(baseTime.getTime() + 177000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-12-1",
          content: "✓ Checking HTTP headers for info leakage",
          args: { url: "https://example.com" },
          toolName: "header_disclosure_test",
          createdAt: new Date(baseTime.getTime() + 180000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-12-2",
          content: "Testing error page information",
          args: { codes: [400, 403, 404, 500] },
          toolName: "error_page_test",
          createdAt: new Date(baseTime.getTime() + 181000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-12-2",
          content: "✓ Testing error page information",
          args: { codes: [400, 403, 404, 500] },
          toolName: "error_page_test",
          createdAt: new Date(baseTime.getTime() + 184000),
        },
        {
          role: "assistant",
          content:
            "Minimal information disclosure:\n- Server header redacted\n- Generic error pages\n- No stack traces exposed",
          createdAt: new Date(baseTime.getTime() + 185000),
        },
      ],
    },
    {
      id: "subagent-13",
      name: "Business Logic Testing",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 190000),
      messages: [
        {
          role: "assistant",
          content: "Testing business logic for security flaws...",
          createdAt: new Date(baseTime.getTime() + 191000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-13-1",
          content: "Testing payment workflow",
          args: { workflow: "checkout" },
          toolName: "business_logic_test",
          createdAt: new Date(baseTime.getTime() + 192000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-13-1",
          content: "✓ Testing payment workflow",
          args: { workflow: "checkout" },
          toolName: "business_logic_test",
          createdAt: new Date(baseTime.getTime() + 198000),
        },
        {
          role: "assistant",
          content:
            "Business logic appears sound. No bypasses found in critical workflows.",
          createdAt: new Date(baseTime.getTime() + 199000),
        },
      ],
    },
    {
      id: "subagent-14",
      name: "Rate Limiting Verification",
      type: "pentest",
      target: "example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 200000),
      messages: [
        {
          role: "assistant",
          content: "Verifying rate limiting implementation...",
          createdAt: new Date(baseTime.getTime() + 201000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-14-1",
          content: "Testing rate limits on login endpoint",
          args: { endpoint: "/login", requests: 100 },
          toolName: "rate_limit_test",
          createdAt: new Date(baseTime.getTime() + 202000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-14-1",
          content: "✓ Testing rate limits on login endpoint",
          args: { endpoint: "/login", requests: 100 },
          toolName: "rate_limit_test",
          createdAt: new Date(baseTime.getTime() + 207000),
        },
        {
          role: "assistant",
          content:
            "Rate limiting properly configured:\n- Login: 5 attempts per 15 min\n- API: 100 requests per hour\n- 429 responses sent appropriately",
          createdAt: new Date(baseTime.getTime() + 208000),
        },
      ],
    },
    {
      id: "subagent-15",
      name: "CORS Configuration Review",
      type: "pentest",
      target: "api.example.com",
      status: "completed",
      createdAt: new Date(baseTime.getTime() + 210000),
      messages: [
        {
          role: "assistant",
          content: "Reviewing CORS policy configuration...",
          createdAt: new Date(baseTime.getTime() + 211000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-15-1",
          content: "Testing CORS headers",
          args: { api: "https://api.example.com" },
          toolName: "cors_test",
          createdAt: new Date(baseTime.getTime() + 212000),
        },
        {
          role: "tool",
          status: "completed",
          toolCallId: "sub-tool-15-1",
          content: "✓ Testing CORS headers",
          args: { api: "https://api.example.com" },
          toolName: "cors_test",
          createdAt: new Date(baseTime.getTime() + 216000),
        },
        {
          role: "assistant",
          content:
            "CORS properly configured with strict origin whitelisting. No wildcard origins.",
          createdAt: new Date(baseTime.getTime() + 217000),
        },
      ],
    },
    {
      id: "subagent-16",
      name: "Content Security Policy Analysis",
      type: "pentest",
      target: "example.com",
      status: "pending",
      createdAt: new Date(baseTime.getTime() + 220000),
      messages: [
        {
          role: "assistant",
          content: "Analyzing Content Security Policy implementation...",
          createdAt: new Date(baseTime.getTime() + 221000),
        },
        {
          role: "tool",
          status: "pending",
          toolCallId: "sub-tool-16-1",
          content: "Reviewing CSP headers",
          args: { url: "https://example.com" },
          toolName: "csp_analysis",
          createdAt: new Date(baseTime.getTime() + 222000),
        },
      ],
    },
  ];

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

  // Simulate streaming by adding messages incrementally
  useEffect(() => {
    if (messageIndex < allMessages.length) {
      const timer = setTimeout(() => {
        setMessages(allMessages.slice(0, messageIndex + 1));
        setMessageIndex(messageIndex + 1);
      }, 50); // Add a message quickly

      return () => clearTimeout(timer);
    } else if (subagentIndex < allSubagents.length) {
      // After all main messages, add subagents
      const timer = setTimeout(() => {
        setSubagents(allSubagents.slice(0, subagentIndex + 1));
        setSubagentIndex(subagentIndex + 1);
      }, 300); // Add a subagent every 300ms

      return () => clearTimeout(timer);
    } else {
      setIsStreaming(false);
    }
  }, [messageIndex, subagentIndex]);

  const toolCallCount = messages.filter((m) => m.role === "tool").length;
  const completedToolCalls = messages.filter(
    (m) => m.role === "tool" && (m as ToolMessage).status === "completed"
  ).length;
  const pendingToolCalls = messages.filter(
    (m) => m.role === "tool" && (m as ToolMessage).status === "pending"
  ).length;

  // Calculate subagent tool calls
  const subagentToolCalls = subagents.reduce((total, subagent) => {
    return total + subagent.messages.filter((m) => m.role === "tool").length;
  }, 0);

  return (
    <box flexDirection="column" width="100%" height="100%">
      {/* Header with stats */}
      <box
        flexDirection="column"
        gap={1}
        padding={1}
        backgroundColor="rgb(40, 40, 40)"
        border={["bottom"]}
        borderColor="green"
      >
        <box flexDirection="row" gap={2}>
          <text fg="green">
            Test Agent Display - Debugging Tool Call & Subagent Visibility
          </text>
        </box>
        <box flexDirection="row" gap={2}>
          <text fg="cyan">
            Main Messages: {messages.length}/{allMessages.length}
          </text>
          <text>|</text>
          <text fg="cyan">Tool Calls: {toolCallCount}</text>
          <text>|</text>
          <text fg="green">Completed: {completedToolCalls}</text>
          <text>|</text>
          <text fg="yellow">Pending: {pendingToolCalls}</text>
        </box>
        <box flexDirection="row" gap={2}>
          <text fg="magenta">
            Subagents: {subagents.length}/{allSubagents.length}
          </text>
          <text>|</text>
          <text fg="magenta">Subagent Tool Calls: {subagentToolCalls}</text>
          <text>|</text>
          <text fg="gray">
            Total Items Rendered: {messages.length + subagents.length}
          </text>
        </box>
      </box>

      {/* Agent display */}
      <AgentDisplay
        messages={messages}
        subagents={subagents}
        isStreaming={isStreaming}
      />

      {/* Footer with instructions */}
      <box
        flexDirection="column"
        gap={1}
        padding={1}
        backgroundColor="rgb(40, 40, 40)"
        border={["top"]}
        borderColor="green"
      >
        <box flexDirection="row" gap={2}>
          <text fg="yellow">
            ⚠ TEST: Click first subagent to open/close it • Watch if subsequent
            subagents disappear
          </text>
        </box>
        <box flexDirection="row" gap={2}>
          <text fg="gray">
            Press Ctrl+C to exit • {subagents.length} of 16 subagents loaded
          </text>
        </box>
      </box>
    </box>
  );
}

render(<App />, {
  exitOnCtrlC: true,
});
