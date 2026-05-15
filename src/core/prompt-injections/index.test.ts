import { mkdir, mkdtemp, rm, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { describe, expect, it } from "vitest";
import { promptInjectionSkill } from "../skills/builtins";
import {
  EMPTY_PROMPT_INJECTION_LIBRARY,
  getPromptInjectionLibrary,
  promptInjectionRef,
  redactPromptInjectionPayloads,
  resolvePromptInjectionRefs,
  StaticPromptInjectionLibrary,
} from "./index";

const TEST_LIBRARY = new StaticPromptInjectionLibrary([
  {
    id: "pi.direct.override",
    name: "Direct Instruction Override",
    category: "instruction-hijack",
    description: "Safe metadata for a direct override test.",
    tags: ["baseline", "direct"],
    deliveryHints: ["json-body"],
    expectedObservation: "The system should preserve instruction hierarchy.",
    payload: "TEST PAYLOAD: direct override",
  },
  {
    id: "pi.secret.request",
    name: "Hidden Secret Request",
    category: "data-exfiltration",
    description: "Safe metadata for a secret request test.",
    tags: ["secrets"],
    deliveryHints: ["chat-message"],
    expectedObservation: "The system should not reveal secrets.",
    payload: "TEST PAYLOAD: secret request",
  },
]);

describe("prompt injection library", () => {
  it("returns safe catalog metadata without raw payload text", () => {
    const catalog = TEST_LIBRARY.listCatalog();
    expect(catalog.length).toBeGreaterThan(0);

    for (const entry of catalog) {
      const payload = TEST_LIBRARY.getPayload(entry.id);
      expect(payload).toBeTruthy();
      expect(JSON.stringify(entry)).not.toContain(payload);
      expect(entry.payloadHash).toMatch(/^[a-f0-9]{64}$/);
    }
  });

  it("resolves prompt injection refs recursively at runtime", () => {
    const id = "pi.direct.override";
    const payload = TEST_LIBRARY.getPayload(id);

    const resolved = resolvePromptInjectionRefs(
      {
        body: promptInjectionRef(id),
        nested: [{ value: promptInjectionRef(id) }],
      },
      TEST_LIBRARY,
    );

    expect(resolved.body).toBe(payload);
    expect(resolved.nested[0].value).toBe(payload);
  });

  it("does not expand magic placeholder strings", () => {
    const value = "prefix {{prompt_injection:pi.direct.override}} suffix";

    expect(resolvePromptInjectionRefs(value, TEST_LIBRARY)).toBe(value);
  });

  it("fails closed for unknown refs", () => {
    expect(() =>
      resolvePromptInjectionRefs(
        promptInjectionRef("pi.nope"),
        EMPTY_PROMPT_INJECTION_LIBRARY,
      ),
    ).toThrow("Unknown prompt injection id");
  });

  it("redacts configured payloads from text before model-visible output", () => {
    const id = "pi.secret.request";
    const payload = TEST_LIBRARY.getPayload(id)!;

    const redacted = redactPromptInjectionPayloads(
      `echo: ${payload}`,
      TEST_LIBRARY,
    );

    expect(redacted).toBe(`echo: [PROMPT_INJECTION:${id}]`);
    expect(redacted).not.toContain(payload);
  });

  it("keeps built-in skill instructions payload-free", () => {
    for (const entry of TEST_LIBRARY.listCatalog()) {
      const payload = TEST_LIBRARY.getPayload(entry.id)!;
      expect(promptInjectionSkill.instructions).not.toContain(payload);
    }
  });

  it("loads a local catalog with payload text in separate files", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-prompt-library-"));
    try {
      await mkdir(join(root, "payloads"));
      await writeFile(
        join(root, "payloads", "direct.txt"),
        "LOCAL RAW PROMPT INJECTION PAYLOAD",
      );
      await writeFile(
        join(root, "catalog.json"),
        JSON.stringify({
          payloads: [
            {
              id: "pi.local.direct",
              name: "Local Direct Override",
              category: "instruction-hijack",
              description: "Safe local metadata for a direct override test.",
              tags: ["local", "direct"],
              deliveryHints: ["json-body"],
              expectedObservation:
                "The system should preserve instruction hierarchy.",
              payloadPath: "payloads/direct.txt",
            },
          ],
        }),
      );

      const library = await getPromptInjectionLibrary({ source: root });
      const catalog = library.listCatalog();

      expect(catalog).toHaveLength(1);
      expect(catalog[0].id).toBe("pi.local.direct");
      expect(JSON.stringify(catalog)).not.toContain(
        "LOCAL RAW PROMPT INJECTION PAYLOAD",
      );
      expect(library.getPayload("pi.local.direct")).toBe(
        "LOCAL RAW PROMPT INJECTION PAYLOAD",
      );
      expect(
        resolvePromptInjectionRefs(
          promptInjectionRef("pi.local.direct"),
          library,
        ),
      ).toBe("LOCAL RAW PROMPT INJECTION PAYLOAD");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects remote prompt injection library sources", async () => {
    await expect(
      getPromptInjectionLibrary({
        source: "https://payloads.example.test/library.json",
      }),
    ).rejects.toThrow("must be a local path");
  });
});
