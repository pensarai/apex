import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

  it("tolerates externally-curated catalogs with novel categories and missing names", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-prompt-library-ext-"));
    try {
      await mkdir(join(root, "payloads"));
      await writeFile(join(root, "payloads", "p0.txt"), "RAW PAYLOAD ZERO");
      await writeFile(join(root, "payloads", "p1.txt"), "RAW PAYLOAD ONE");
      await writeFile(
        join(root, "catalog.json"),
        JSON.stringify({
          payloads: [
            {
              // No `name`, a category outside Apex's built-in set, and no
              // `description` — the loader must still accept this entry.
              id: "pi.ext.jailbreak",
              category: "jailbreak",
              payloadPath: "payloads/p0.txt",
            },
            {
              id: "pi.ext.exfil",
              name: "Exfil Variant",
              category: "data-exfiltration",
              tags: ["exfil"],
              payloadPath: "payloads/p1.txt",
            },
          ],
        }),
      );

      const library = await getPromptInjectionLibrary({ source: root });
      const catalog = library.listCatalog();

      expect(catalog).toHaveLength(2);

      const jailbreak = catalog.find((e) => e.id === "pi.ext.jailbreak")!;
      expect(jailbreak.category).toBe("jailbreak");
      // Missing name falls back to the id.
      expect(jailbreak.name).toBe("pi.ext.jailbreak");
      expect(jailbreak.description).toBe("");
      expect(jailbreak.tags).toEqual([]);

      // Payload text is still resolvable but never present in the catalog.
      expect(library.getPayload("pi.ext.jailbreak")).toBe("RAW PAYLOAD ZERO");
      expect(JSON.stringify(catalog)).not.toContain("RAW PAYLOAD ZERO");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("accepts catalogs that name fields `path`/`title` (L1B3RT4S schemaVersion 1)", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-prompt-library-l1b-"));
    try {
      await mkdir(join(root, "payloads", "anthropic"), { recursive: true });
      await writeFile(
        join(root, "payloads", "anthropic", "00-opus.txt"),
        "RAW L1B3RT4S PAYLOAD",
      );
      await writeFile(
        join(root, "catalog.json"),
        JSON.stringify({
          schemaVersion: 1,
          name: "L1B3RT4S prompt-injection payload library",
          payloads: [
            {
              id: "anthropic-opus-1",
              title: "Anthropic Opus",
              category: "anthropic",
              vendor: "Anthropic (Claude)",
              path: "payloads/anthropic/00-opus.txt",
              sourceFile: "ANTHROPIC.mkd",
              bytes: 19,
              sha256: "ignored",
              techniques: ["invisible-unicode"],
              tags: ["jailbreak", "prompt-injection"],
            },
          ],
        }),
      );

      const library = await getPromptInjectionLibrary({ source: root });
      const catalog = library.listCatalog();

      expect(catalog).toHaveLength(1);
      const entry = catalog[0];
      expect(entry.id).toBe("anthropic-opus-1");
      // `title` is normalized to `name`.
      expect(entry.name).toBe("Anthropic Opus");
      expect(entry.category).toBe("anthropic");
      // `path` is normalized to the payload pointer and resolves the file.
      expect(library.getPayload("anthropic-opus-1")).toBe(
        "RAW L1B3RT4S PAYLOAD",
      );
      // Unknown extra fields never leak into the safe catalog metadata.
      expect(JSON.stringify(entry)).not.toContain("sourceFile");
      expect(JSON.stringify(entry)).not.toContain("RAW L1B3RT4S PAYLOAD");
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
