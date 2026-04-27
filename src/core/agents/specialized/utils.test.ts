import { describe, expect, it } from "vitest";
import { detectOSAndEnhancePrompt } from "./utils";

const STUB = "STUB SYSTEM PROMPT";

describe("detectOSAndEnhancePrompt", () => {
  it("preserves the original prompt at the end of the output", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    expect(out.endsWith(STUB)).toBe(true);
  });

  it("emits an [ENV CONTEXT] block with OS info", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    expect(out).toContain("[ENV CONTEXT]");
    expect(out).toContain("[/ENV CONTEXT]");
    expect(out).toMatch(/OS: .* \| InDocker: (yes|no) \| Kali: (yes|no)/);
  });

  it("emits a [BUNDLED ASSETS] block with all three tier variables", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    expect(out).toContain("[BUNDLED ASSETS]");
    expect(out).toContain("[/BUNDLED ASSETS]");
    expect(out).toMatch(/TINY_WORDLIST=\S+tiny\.txt/);
    expect(out).toMatch(/DEFAULT_WORDLIST=\S+common\.txt/);
    expect(out).toMatch(/LARGE_WORDLIST=\S+large\.txt/);
  });

  it("includes the reactive disclaimer to prevent prescriptive prompt drift", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    expect(out).toContain("NOT a reason to run a wordlist-based tool");
    expect(out).toContain("Do NOT chain tiers automatically");
  });

  it("frames the block as a capability inventory for self-introspection", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    expect(out).toContain("authoritative inventory");
    expect(out).toMatch(/answer directly from the entries below/);
  });

  it("instructs the agent not to probe the filesystem when asked about wordlists", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    expect(out).toContain("do NOT probe the filesystem");
    expect(out).toContain("/usr/share/wordlists");
    expect(out).toContain("which gobuster");
  });

  it("broadens use beyond -w args to include line-by-line iteration", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    expect(out).toMatch(/iterated line-by-line/);
    expect(out).toContain("http_request");
  });

  it("forbids hardcoded /usr/share/wordlists paths", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    expect(out).toContain("Do NOT assume /usr/share/wordlists/* exists");
  });

  it("does not encode operator-mode escalation rules (those live in the operator prompt)", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    expect(out).not.toContain("Operator mode:");
    expect(out).not.toContain("ask the user via the `response` tool");
  });

  it("places [BUNDLED ASSETS] after [ENV CONTEXT] and before the original prompt", () => {
    const out = detectOSAndEnhancePrompt(STUB);
    const envIdx = out.indexOf("[/ENV CONTEXT]");
    const bundledIdx = out.indexOf("[BUNDLED ASSETS]");
    const stubIdx = out.indexOf(STUB);
    expect(envIdx).toBeGreaterThan(-1);
    expect(bundledIdx).toBeGreaterThan(envIdx);
    expect(stubIdx).toBeGreaterThan(bundledIdx);
  });
});
