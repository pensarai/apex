import { WHITEBOX_CATALOG } from "./profiles";
import type {
  CatalogRecord,
  CatalogRecordKind,
  CatalogSelection,
  LanguageId,
  RepoProfile,
} from "./types";

function languageMatches(
  record: CatalogRecord,
  languages: LanguageId[],
): boolean {
  if (!record.languages || record.languages.length === 0) return true;
  return record.languages.some((language) => languages.includes(language));
}

function textMatches(record: CatalogRecord, query: string): boolean {
  if (!query) return true;
  const haystack = [
    record.id,
    record.title,
    record.kind,
    record.guidance,
    ...(record.tags ?? []),
    ...(record.patterns ?? []),
    ...(record.tools ?? []),
  ]
    .join(" ")
    .toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((term) => haystack.includes(term));
}

export function queryWhiteboxCatalog(input: {
  profile?: RepoProfile;
  query?: string;
  kind?: CatalogRecordKind;
  tags?: string[];
  limit?: number;
}): CatalogRecord[] {
  const languages = input.profile?.languages ?? [];
  const requiredTags = input.tags ?? [];
  const limit = Math.min(50, Math.max(1, Math.floor(input.limit ?? 12)));

  return WHITEBOX_CATALOG.filter((record) => {
    if (input.kind && record.kind !== input.kind) return false;
    if (languages.length > 0 && !languageMatches(record, languages)) {
      return false;
    }
    if (
      requiredTags.length > 0 &&
      !requiredTags.every((tag) => record.tags.includes(tag))
    ) {
      return false;
    }
    return textMatches(record, input.query ?? "");
  }).slice(0, limit);
}

export function selectCatalogForProfile(
  profile: RepoProfile,
): CatalogSelection {
  const records = queryWhiteboxCatalog({ profile, limit: 30 });
  const recommendedPasses = records
    .filter((record) => record.kind === "review-pass")
    .slice(0, 8);

  return { records, recommendedPasses };
}

export function summarizeCatalogRecords(records: CatalogRecord[]): string[] {
  return records.map((record) => {
    const scope = record.languages?.length
      ? ` [${record.languages.join(", ")}]`
      : "";
    return `${record.id}${scope}: ${record.title}`;
  });
}
