interface CatalogEntry {
  id: string;
  pricing: Record<string, string>;
}

export function findPricing(
  catalog: CatalogEntry[],
  model: string,
): CatalogEntry | undefined {
  const exact = catalog.find((entry) => entry.id === model);
  if (exact) return exact;
  if (model.includes("/")) return undefined;
  const normalize = (id: string) => id.replace(/(\d)\.(\d)/g, "$1-$2");
  const matches = catalog.filter(
    (entry) =>
      normalize(entry.id.slice(entry.id.lastIndexOf("/") + 1)) ===
      normalize(model),
  );
  return matches.length === 1 ? matches[0] : undefined;
}
