// Test-only (knip ignores __tests__/). zod writes a nullable field as
// `type: ["number", "null"]` when the inner schema is a bare type and as
// `anyOf` otherwise; both accept the same values.

export interface WireSchemaProperty {
  type?: string | string[];
  anyOf?: WireSchemaProperty[];
  description?: string;
}

/** The JSON types a property accepts, in schema order. */
export function acceptedTypes(
  property: WireSchemaProperty | undefined,
): string[] {
  if (!property) return [];
  if (property.anyOf) return property.anyOf.flatMap(acceptedTypes);
  if (property.type === undefined) return [];
  return Array.isArray(property.type) ? property.type : [property.type];
}
