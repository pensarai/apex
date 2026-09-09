import { describe, expect, it } from "vitest";
import { stripEnvAssignmentPrefix } from "./shell-command";

describe("stripEnvAssignmentPrefix", () => {
  it("strips a single export prefix joined with &&", () => {
    expect(
      stripEnvAssignmentPrefix(
        'export PATH="/opt/tools/bin:$PATH" && nmap -sV target',
      ),
    ).toBe("nmap -sV target");
  });

  it("strips chained export prefixes", () => {
    expect(
      stripEnvAssignmentPrefix(
        'export BUN_INSTALL="$HOME/.bun" && export PATH="$BUN_INSTALL/bin:$PATH" && bun install',
      ),
    ).toBe("bun install");
  });

  it("strips inline space-separated assignments without export", () => {
    expect(
      stripEnvAssignmentPrefix("FOO=bar BAR=baz ./scanner --target x"),
    ).toBe("./scanner --target x");
  });

  it("strips assignments separated by semicolons", () => {
    expect(stripEnvAssignmentPrefix("FOO=bar; nmap target")).toBe(
      "nmap target",
    );
  });

  it("leaves a plain command untouched", () => {
    expect(stripEnvAssignmentPrefix("nmap -sV target")).toBe("nmap -sV target");
  });

  it("does not treat a command's own flags as assignments", () => {
    expect(stripEnvAssignmentPrefix('curl -H "X-Test: y" http://host')).toBe(
      'curl -H "X-Test: y" http://host',
    );
  });

  it("falls back to the original when only assignments are present", () => {
    expect(stripEnvAssignmentPrefix("FOO=bar")).toBe("FOO=bar");
  });

  it("trims surrounding whitespace", () => {
    expect(stripEnvAssignmentPrefix("  export A=1 && id  ")).toBe("id");
  });
});
