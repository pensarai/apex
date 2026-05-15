import { z } from "zod";

/** Minimal JSON-Schema → zod converter. Unsupported keywords are ignored. */
export function jsonSchemaToZod(schema: unknown): z.ZodTypeAny {
  if (schema === undefined || schema === null) {
    throw new Error("jsonSchemaToZod: schema is null/undefined");
  }
  if (typeof schema !== "object") {
    throw new Error("jsonSchemaToZod: schema must be an object");
  }
  const s = schema as Record<string, unknown>;

  if ("const" in s) {
    return z.literal(s.const as z.Primitive);
  }

  if (Array.isArray(s.enum)) {
    const values = s.enum as Array<z.Primitive>;
    if (values.length === 0) {
      throw new Error("jsonSchemaToZod: enum array is empty");
    }
    if (values.length === 1) return z.literal(values[0]);
    return z.union(
      values.map((v) => z.literal(v)) as unknown as [
        z.ZodTypeAny,
        z.ZodTypeAny,
        ...z.ZodTypeAny[],
      ],
    );
  }

  const union = (s.anyOf ?? s.oneOf) as unknown[] | undefined;
  if (Array.isArray(union) && union.length > 0) {
    const parts = union.map((sub) => jsonSchemaToZod(sub));
    if (parts.length === 1) return parts[0];
    return z.union(parts as [z.ZodTypeAny, z.ZodTypeAny, ...z.ZodTypeAny[]]);
  }

  const nullable = s.nullable === true;

  if (Array.isArray(s.type)) {
    const parts = (s.type as string[]).map((t) =>
      jsonSchemaToZod({ ...s, type: t }),
    );
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
      const inner = s.items ? jsonSchemaToZod(s.items) : z.unknown();
      let arr = z.array(inner);
      if (typeof s.minItems === "number") arr = arr.min(s.minItems);
      if (typeof s.maxItems === "number") arr = arr.max(s.maxItems);
      zodSchema = arr;
      break;
    }
    case "object": {
      const properties = (s.properties ?? {}) as Record<string, unknown>;
      const required = new Set(
        Array.isArray(s.required) ? (s.required as string[]) : [],
      );
      const shape: Record<string, z.ZodTypeAny> = {};
      for (const [key, value] of Object.entries(properties)) {
        const child = jsonSchemaToZod(value);
        shape[key] = required.has(key) ? child : child.optional();
      }
      const additional = s.additionalProperties;
      if (additional === false) {
        zodSchema = z.object(shape).strict();
      } else if (additional && typeof additional === "object") {
        zodSchema = z.object(shape).catchall(jsonSchemaToZod(additional));
      } else {
        zodSchema = z.object(shape).passthrough();
      }
      break;
    }
    default:
      // Untyped schema → accept anything; lets parent agents pass partial schemas.
      zodSchema = z.unknown();
  }

  return nullable ? zodSchema.nullable() : zodSchema;
}
