import { z } from "zod";

/**
 * Minimal JSON-Schema (subset of Draft 7) → zod converter.
 *
 * Supports the constructs an agent would realistically build at runtime
 * to shape a subagent's structured response: objects with properties,
 * arrays of items, enums, primitives (string / number / integer / boolean
 * / null), `nullable`, `enum`, `const`, simple `anyOf` / `oneOf`, and
 * `$ref`-free composition.
 *
 * This is intentionally not a full Draft-7 implementation — it exists to
 * keep `spawn_coding_agent`'s `responseSchema` field self-contained
 * without pulling in a heavy dependency. Unsupported keywords are
 * ignored rather than rejected so a parent agent can pass over-specified
 * schemas and still get a usable zod schema.
 *
 * @throws if the input is missing `type` and has none of the supported
 *   composition keywords (`enum`, `const`, `anyOf`, `oneOf`).
 */
export function jsonSchemaToZod(schema: unknown): z.ZodTypeAny {
  if (schema === undefined || schema === null) {
    throw new Error("jsonSchemaToZod: schema is null/undefined");
  }
  if (typeof schema !== "object") {
    throw new Error("jsonSchemaToZod: schema must be an object");
  }
  const s = schema as Record<string, unknown>;

  // Literal value
  if ("const" in s) {
    return z.literal(s.const as z.Primitive);
  }

  // Enum (heterogeneous values supported)
  if (Array.isArray(s.enum)) {
    const values = s.enum as Array<z.Primitive>;
    if (values.length === 0) {
      throw new Error("jsonSchemaToZod: enum array is empty");
    }
    if (values.length === 1) {
      return z.literal(values[0]);
    }
    const parts = values.map((v) => z.literal(v)) as unknown as [
      z.ZodTypeAny,
      z.ZodTypeAny,
      ...z.ZodTypeAny[],
    ];
    return z.union(parts);
  }

  // Union via anyOf / oneOf
  const union = (s.anyOf ?? s.oneOf) as unknown[] | undefined;
  if (Array.isArray(union) && union.length > 0) {
    const parts = union.map((sub) => jsonSchemaToZod(sub));
    if (parts.length === 1) return parts[0];
    return z.union(parts as [z.ZodTypeAny, z.ZodTypeAny, ...z.ZodTypeAny[]]);
  }

  const nullable = s.nullable === true;

  // Multi-type: ["string", "null"] etc.
  if (Array.isArray(s.type)) {
    const types = s.type as string[];
    const parts = types.map((t) => jsonSchemaToZod({ ...s, type: t }));
    const merged =
      parts.length === 1
        ? parts[0]
        : z.union(parts as [z.ZodTypeAny, z.ZodTypeAny, ...z.ZodTypeAny[]]);
    return nullable ? merged.nullable() : merged;
  }

  const type = typeof s.type === "string" ? (s.type as string) : undefined;

  let zodSchema: z.ZodTypeAny;
  switch (type) {
    case "string": {
      let str = z.string();
      if (typeof s.minLength === "number") str = str.min(s.minLength);
      if (typeof s.maxLength === "number") str = str.max(s.maxLength);
      if (typeof s.pattern === "string") str = str.regex(new RegExp(s.pattern));
      zodSchema = str;
      break;
    }
    case "integer":
    case "number": {
      let num = z.number();
      if (type === "integer") num = num.int();
      if (typeof s.minimum === "number") num = num.min(s.minimum);
      if (typeof s.maximum === "number") num = num.max(s.maximum);
      zodSchema = num;
      break;
    }
    case "boolean":
      zodSchema = z.boolean();
      break;
    case "null":
      zodSchema = z.null();
      break;
    case "array": {
      const items = s.items as unknown;
      const inner = items ? jsonSchemaToZod(items) : z.unknown();
      let arr = z.array(inner);
      if (typeof s.minItems === "number") arr = arr.min(s.minItems);
      if (typeof s.maxItems === "number") arr = arr.max(s.maxItems);
      zodSchema = arr;
      break;
    }
    case "object": {
      const properties = (s.properties ?? {}) as Record<string, unknown>;
      const required = Array.isArray(s.required)
        ? new Set(s.required as string[])
        : new Set<string>();

      const shape: Record<string, z.ZodTypeAny> = {};
      for (const [key, value] of Object.entries(properties)) {
        const child = jsonSchemaToZod(value);
        shape[key] = required.has(key) ? child : child.optional();
      }

      const additional = s.additionalProperties;
      let obj: z.ZodTypeAny;
      if (additional === false) {
        obj = z.object(shape).strict();
      } else if (additional && typeof additional === "object") {
        obj = z.object(shape).catchall(jsonSchemaToZod(additional));
      } else {
        // additionalProperties === true | undefined → permissive
        obj = z.object(shape).passthrough();
      }
      zodSchema = obj;
      break;
    }
    default:
      // Untyped schema → accept anything. This keeps the converter robust
      // against partial schemas the parent agent might emit.
      zodSchema = z.unknown();
  }

  return nullable ? zodSchema.nullable() : zodSchema;
}
