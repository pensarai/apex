import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  type AttemptEvidence,
  type AttemptTokens,
  type AttemptTransport,
  adaptTransportUsage,
  type ProviderAttemptValidationCode,
  ProviderAttemptValidationError,
} from "./index";

interface AttemptFixture {
  transport: AttemptTransport;
  usage?: unknown;
  providerMetadata?: unknown;
  providerRequestId?: string;
  cacheTtlSeconds?: number;
  cacheBreakpoint?: AttemptEvidence["cacheBreakpoint"];
  expected?: {
    tokens: AttemptTokens;
    evidence?: Partial<AttemptEvidence>;
  };
  reject?: ProviderAttemptValidationCode;
}

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

function loadFixtures(): Array<{ name: string; fixture: AttemptFixture }> {
  return readdirSync(fixturesDir)
    .filter((file) => file.endsWith(".json"))
    .sort()
    .map((file) => ({
      name: file.replace(/\.json$/, ""),
      fixture: JSON.parse(
        readFileSync(join(fixturesDir, file), "utf8"),
      ) as AttemptFixture,
    }));
}

const fixtures = loadFixtures();
const accepted = fixtures.filter((entry) => !entry.fixture.reject);
const rejected = fixtures.filter((entry) => entry.fixture.reject);

describe("adaptTransportUsage fixtures", () => {
  it("loads accept and reject fixtures", () => {
    expect(accepted.length).toBeGreaterThan(0);
    expect(rejected.length).toBeGreaterThan(0);
  });

  it.each(accepted)("$name normalizes to the expected tokens", ({
    fixture,
  }) => {
    const adapted = adaptTransportUsage({
      transport: fixture.transport,
      usage: fixture.usage,
      providerMetadata: fixture.providerMetadata,
      providerRequestId: fixture.providerRequestId,
      cacheTtlSeconds: fixture.cacheTtlSeconds,
      cacheBreakpoint: fixture.cacheBreakpoint,
    });
    expect(adapted.tokens).toEqual(fixture.expected?.tokens);
    if (fixture.expected?.evidence) {
      expect(adapted.evidence).toMatchObject(fixture.expected.evidence);
    }
  });

  it.each(rejected)("$name rejects with $fixture.reject", ({ fixture }) => {
    try {
      adaptTransportUsage({
        transport: fixture.transport,
        usage: fixture.usage,
        providerMetadata: fixture.providerMetadata,
      });
      expect.unreachable("expected contradictory usage to be rejected");
    } catch (error) {
      expect(error).toBeInstanceOf(ProviderAttemptValidationError);
      expect((error as ProviderAttemptValidationError).code).toBe(
        fixture.reject,
      );
    }
  });
});
