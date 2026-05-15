import { describe, expect, it } from "vitest";
import { jsonSchemaToZod } from "./jsonSchemaToZod";

describe("jsonSchemaToZod", () => {
  it("converts primitive strings", () => {
    const zod = jsonSchemaToZod({ type: "string" });
    expect(zod.safeParse("hi").success).toBe(true);
    expect(zod.safeParse(123).success).toBe(false);
  });

  it("converts integers vs numbers", () => {
    const int = jsonSchemaToZod({ type: "integer" });
    const num = jsonSchemaToZod({ type: "number" });
    expect(int.safeParse(3).success).toBe(true);
    expect(int.safeParse(3.5).success).toBe(false);
    expect(num.safeParse(3.5).success).toBe(true);
  });

  it("respects string min/max/pattern", () => {
    const zod = jsonSchemaToZod({
      type: "string",
      minLength: 2,
      maxLength: 5,
      pattern: "^[a-z]+$",
    });
    expect(zod.safeParse("ab").success).toBe(true);
    expect(zod.safeParse("a").success).toBe(false);
    expect(zod.safeParse("abcdef").success).toBe(false);
    expect(zod.safeParse("AB").success).toBe(false);
  });

  it("converts arrays of primitives", () => {
    const zod = jsonSchemaToZod({
      type: "array",
      items: { type: "string" },
      minItems: 1,
    });
    expect(zod.safeParse(["a", "b"]).success).toBe(true);
    expect(zod.safeParse([]).success).toBe(false);
    expect(zod.safeParse([1, 2]).success).toBe(false);
  });

  it("converts objects with required + optional properties", () => {
    const zod = jsonSchemaToZod({
      type: "object",
      properties: {
        name: { type: "string" },
        age: { type: "integer" },
      },
      required: ["name"],
    });
    expect(zod.safeParse({ name: "x" }).success).toBe(true);
    expect(zod.safeParse({ name: "x", age: 30 }).success).toBe(true);
    expect(zod.safeParse({ age: 30 }).success).toBe(false);
  });

  it("supports enum and const", () => {
    const zEnum = jsonSchemaToZod({ enum: ["low", "high"] });
    expect(zEnum.safeParse("low").success).toBe(true);
    expect(zEnum.safeParse("other").success).toBe(false);

    const zConst = jsonSchemaToZod({ const: "x" });
    expect(zConst.safeParse("x").success).toBe(true);
    expect(zConst.safeParse("y").success).toBe(false);
  });

  it("supports nullable + multi-type", () => {
    const z1 = jsonSchemaToZod({ type: "string", nullable: true });
    expect(z1.safeParse(null).success).toBe(true);
    expect(z1.safeParse("hi").success).toBe(true);

    const z2 = jsonSchemaToZod({ type: ["string", "null"] });
    expect(z2.safeParse(null).success).toBe(true);
    expect(z2.safeParse("hi").success).toBe(true);
    expect(z2.safeParse(1).success).toBe(false);
  });

  it("supports anyOf composition", () => {
    const zod = jsonSchemaToZod({
      anyOf: [{ type: "string" }, { type: "integer" }],
    });
    expect(zod.safeParse("hi").success).toBe(true);
    expect(zod.safeParse(3).success).toBe(true);
    expect(zod.safeParse(true).success).toBe(false);
  });

  it("converts nested object/array combinations", () => {
    const zod = jsonSchemaToZod({
      type: "object",
      properties: {
        findings: {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: "string" },
              severity: { enum: ["low", "high"] },
            },
            required: ["id", "severity"],
          },
        },
      },
      required: ["findings"],
    });
    const ok = zod.safeParse({
      findings: [{ id: "a", severity: "low" }],
    });
    expect(ok.success).toBe(true);
    const bad = zod.safeParse({ findings: [{ id: "a", severity: "med" }] });
    expect(bad.success).toBe(false);
  });

  it("rejects additional properties when additionalProperties=false", () => {
    const zod = jsonSchemaToZod({
      type: "object",
      properties: { a: { type: "string" } },
      required: ["a"],
      additionalProperties: false,
    });
    expect(zod.safeParse({ a: "x" }).success).toBe(true);
    expect(zod.safeParse({ a: "x", b: 1 }).success).toBe(false);
  });
});
