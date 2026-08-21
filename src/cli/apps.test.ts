import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CLI = join(import.meta.dirname, "apps.ts");

// Every case below fails before any API call, so these stay offline.
function runApps(args: string[]) {
  const result = spawnSync("bun", [CLI, ...args], { encoding: "utf8" });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

describe("pensar apps CLI", () => {
  it("advertises the domain subcommands and transport flag", () => {
    const { status, stdout } = runApps(["--help"]);

    expect(status).toBe(0);
    expect(stdout).toContain("pensar apps domains");
    expect(stdout).toContain("pensar apps domain-create <domain>");
    expect(stdout).toContain("--transport <transport>");
    expect(stdout).toContain("http, grpc, grpc_web, connect");
  });

  it("rejects an unknown endpoint transport", () => {
    const { status, stderr } = runApps([
      "endpoint-create",
      "app-1",
      "--endpoint",
      "/v1/orders",
      "--description",
      "Orders",
      "--transport",
      "carrier-pigeon",
    ]);

    expect(status).toBe(1);
    expect(stderr).toContain('Invalid --transport "carrier-pigeon"');
    expect(stderr).toContain("http, grpc, grpc_web, connect");
  });

  it("rejects an unknown transport on endpoint-update", () => {
    const { status, stderr } = runApps([
      "endpoint-update",
      "endpoint-1",
      "--transport",
      "smoke-signal",
    ]);

    expect(status).toBe(1);
    expect(stderr).toContain('Invalid --transport "smoke-signal"');
  });

  it("requires a domain argument for domain-create", () => {
    const { status, stderr } = runApps(["domain-create"]);

    expect(status).toBe(1);
    expect(stderr).toContain("Usage: pensar apps domain-create <domain>");
  });
});
