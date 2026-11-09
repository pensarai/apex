import { describe, expect, it } from "vitest";
import { type MermaidTopology, topologyToMermaid } from "./topologyMermaid";

const system: MermaidTopology = {
  boundaries: [
    { name: "Private subnets", kind: "subnet", parent: "Console VPC" },
    { name: "AWS account", kind: "cloud-account" },
    { name: "Console VPC", kind: "vpc", parent: "AWS account" },
    { name: "User devices", kind: "user-device" },
  ],
  components: [
    {
      name: "Aurora PostgreSQL",
      kind: "database",
      boundary: "Private subnets",
      exposure: "private",
    },
    {
      name: "Console Web",
      kind: "application",
      boundary: "Private subnets",
      exposure: "public",
    },
    {
      name: "Android app",
      kind: "client",
      boundary: "User devices",
      exposure: "public",
    },
    {
      name: "API gateway",
      kind: "entrypoint",
      boundary: "AWS account",
      exposure: "public",
    },
    {
      name: "Jobs",
      kind: "queue",
      boundary: "AWS account",
      exposure: "private",
    },
  ],
  flows: [
    { from: "Console Web", to: "Aurora PostgreSQL", label: "SQL" },
    { from: "API gateway", to: "Console Web", label: "HTTPS" },
    { from: "Android app", to: "API gateway", label: "HTTPS" },
    { from: "Console Web", to: "Jobs", label: "enqueue" },
  ],
  controls: [
    {
      name: "Session auth",
      appliesTo: ["Console Web"],
      gaps: "Trusts the X-User header.",
    },
    { name: "Private subnet isolation", appliesTo: ["Private subnets"] },
  ],
};

describe("topologyToMermaid", () => {
  it("nests boundaries as subgraphs and places each component inside its own", () => {
    const lines = topologyToMermaid(system).split("\n");
    const at = (needle: string) => lines.findIndex((l) => l.includes(needle));
    const account = at('subgraph b_aws_account["AWS account (cloud-account)"]');
    const vpc = at('subgraph b_console_vpc["Console VPC (vpc)"]');
    const subnet = at('subgraph b_private_subnets["Private subnets (subnet)"]');
    const aurora = at("c_aurora_postgresql");
    expect(account).toBeGreaterThan(0);
    expect(vpc).toBeGreaterThan(account);
    expect(subnet).toBeGreaterThan(vpc);
    expect(aurora).toBeGreaterThan(subnet);
    // Indentation is the nesting depth: account(1) > vpc(2) > subnet(3) > aurora(4).
    expect(lines[aurora]).toMatch(/^ {8}c_aurora_postgresql/);
    // Every subgraph is closed.
    const opened = lines.filter((l) => l.trim().startsWith("subgraph ")).length;
    expect(lines.filter((l) => l.trim() === "end")).toHaveLength(opened);
  });

  it("shapes nodes by kind and marks public components", () => {
    const out = topologyToMermaid(system);
    expect(out).toContain(
      'c_aurora_postgresql[("Aurora PostgreSQL (database)")]',
    );
    expect(out).toContain('c_jobs[["Jobs (queue)"]]');
    expect(out).toContain(
      'c_api_gateway{{"API gateway (entrypoint)"}}:::public',
    );
    expect(out).toContain('c_android_app(["Android app (client)"]):::public');
    expect(out).toContain(
      'c_console_web["Console Web (application)"]:::public',
    );
  });

  it("draws flows as labeled edges between component ids", () => {
    const out = topologyToMermaid(system);
    expect(out).toContain('c_console_web -->|"SQL"| c_aurora_postgresql');
    expect(out).toContain('c_android_app -->|"HTTPS"| c_api_gateway');
  });

  it("is deterministic regardless of input order", () => {
    const shuffled: MermaidTopology = {
      boundaries: [...system.boundaries].reverse(),
      components: [...system.components].reverse(),
      flows: [...system.flows].reverse(),
      controls: [...(system.controls ?? [])].reverse(),
    };
    expect(topologyToMermaid(shuffled, { controls: true })).toBe(
      topologyToMermaid(system, { controls: true }),
    );
  });

  it("escapes characters that would break Mermaid syntax", () => {
    const out = topologyToMermaid({
      boundaries: [],
      components: [
        { name: 'Edge "prod" <nginx>', kind: "proxy", boundary: "none" },
        { name: "API #2", kind: "application", boundary: "none" },
      ],
      flows: [
        { from: 'Edge "prod" <nginx>', to: "API #2", label: "/v1 | /v2" },
      ],
    });
    expect(out).toContain("Edge #quot;prod#quot; #lt;nginx#gt; (proxy)");
    expect(out).toContain("API #35;2 (application)");
    expect(out).toContain('|"/v1 #124; /v2"|');
    expect(out).not.toMatch(/"[^"\n]*"[^"\n]*prod/);
  });

  it("gives names that slug alike distinct ids", () => {
    const out = topologyToMermaid({
      boundaries: [],
      components: [
        { name: "API v2", kind: "application", boundary: "x" },
        { name: "API-v2", kind: "application", boundary: "x" },
      ],
      flows: [{ from: "API-v2", to: "API v2", label: "proxy" }],
    });
    expect(out).toContain('c_api_v2["API v2 (application)"]');
    expect(out).toContain('c_api_v2_2["API-v2 (application)"]');
    expect(out).toContain('c_api_v2_2 -->|"proxy"| c_api_v2');
  });

  it("collapses repeated flow records and resolves names case-insensitively", () => {
    const out = topologyToMermaid({
      ...system,
      flows: [
        { from: "Console Web", to: "Aurora PostgreSQL", label: "SQL" },
        { from: "console web", to: "aurora postgresql", label: "sql" },
      ],
    });
    expect(out.match(/-->/g)).toHaveLength(1);
  });

  it("draws a flow to an undocumented component as a marked node, not a silent drop", () => {
    const out = topologyToMermaid({
      ...system,
      flows: [{ from: "Console Web", to: "Redis", label: "cache" }],
    });
    expect(out).toContain('missing_redis["Redis (undocumented)"]:::missing');
    expect(out).toContain('c_console_web -->|"cache"| missing_redis');
  });

  it("draws controls only when asked, linked to components and boundaries, flagging gaps", () => {
    expect(topologyToMermaid(system)).not.toContain("ctl_");
    const out = topologyToMermaid(system, { controls: true });
    expect(out).toContain('ctl_session_auth>"Session auth"]:::gap');
    expect(out).toContain("ctl_session_auth -.-> c_console_web");
    expect(out).toContain(
      'ctl_private_subnet_isolation>"Private subnet isolation"]\n',
    );
    expect(out).toContain(
      "ctl_private_subnet_isolation -.-> b_private_subnets",
    );
  });
});
