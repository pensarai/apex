import { createHash } from "crypto";
import type { HarEntry, HarHeader } from "./types";

export type HarDiffBucket =
  | "same-response"
  | "different-but-200"
  | "403-vs-200"
  | "unique-to-a"
  | "unique-to-b";

export interface HarDiffCandidate {
  bucket: HarDiffBucket;
  score: number;
  key: string;
  accountA?: CompactHarEntry;
  accountB?: CompactHarEntry;
}

export interface CompactHarEntry {
  id?: string;
  method: string;
  url: string;
  requestAuth: {
    authorization?: string;
    cookie?: string;
  };
  response: {
    status: number;
    contentType?: string;
    setCookie?: string;
    size: number;
    bodySha: string;
  };
}

export interface HarDiffReport {
  generatedAt: string;
  counts: {
    accountAEntries: number;
    accountBEntries: number;
    candidates: number;
  };
  candidates: HarDiffCandidate[];
}

export function diffHarEntries(
  accountAEntries: HarEntry[],
  accountBEntries: HarEntry[],
): HarDiffReport {
  const byKeyB = new Map(
    accountBEntries.map((entry) => [canonicalKey(entry), entry]),
  );
  const seenB = new Set<string>();
  const candidates: HarDiffCandidate[] = [];

  for (const accountA of accountAEntries) {
    const key = canonicalKey(accountA);
    const accountB = byKeyB.get(key);
    if (!accountB) {
      candidates.push({
        bucket: "unique-to-a",
        score: suspicionScore("unique-to-a"),
        key,
        accountA: compactHarEntry(accountA),
      });
      continue;
    }

    seenB.add(key);
    const bucket = bucketPair(accountA, accountB);
    candidates.push({
      bucket,
      score: suspicionScore(bucket),
      key,
      accountA: compactHarEntry(accountA),
      accountB: compactHarEntry(accountB),
    });
  }

  for (const accountB of accountBEntries) {
    const key = canonicalKey(accountB);
    if (seenB.has(key)) continue;
    candidates.push({
      bucket: "unique-to-b",
      score: suspicionScore("unique-to-b"),
      key,
      accountB: compactHarEntry(accountB),
    });
  }

  candidates.sort((a, b) => b.score - a.score);
  return {
    generatedAt: new Date().toISOString(),
    counts: {
      accountAEntries: accountAEntries.length,
      accountBEntries: accountBEntries.length,
      candidates: candidates.length,
    },
    candidates,
  };
}

function canonicalKey(entry: HarEntry): string {
  const url = new URL(entry.request.url);
  const params = Array.from(url.searchParams.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
  const body = entry.request.postData?.text ?? "";
  const bodyHash = body
    ? createHash("sha256").update(body).digest("hex").slice(0, 12)
    : "";
  return [
    entry.request.method.toUpperCase(),
    url.host,
    url.pathname,
    params,
    bodyHash,
  ].join(" ");
}

function responseHash(entry: HarEntry): string {
  const content = entry.response.content;
  return createHash("sha256")
    .update(
      `${entry.response.status}:${content.size}:${content.text ?? content._attachedSha ?? ""}`,
    )
    .digest("hex");
}

function headerValue(headers: HarHeader[], name: string): string | undefined {
  const lower = name.toLowerCase();
  return headers.find((header) => header.name.toLowerCase() === lower)?.value;
}

function compactHarEntry(entry: HarEntry): CompactHarEntry {
  return {
    id: entry._id,
    method: entry.request.method,
    url: entry.request.url,
    requestAuth: {
      authorization: headerValue(entry.request.headers, "authorization"),
      cookie: headerValue(entry.request.headers, "cookie"),
    },
    response: {
      status: entry.response.status,
      contentType: headerValue(entry.response.headers, "content-type"),
      setCookie: headerValue(entry.response.headers, "set-cookie"),
      size: entry.response.content.size,
      bodySha: entry.response.content._attachedSha ?? responseHash(entry),
    },
  };
}

function bucketPair(accountA: HarEntry, accountB: HarEntry): HarDiffBucket {
  if (
    (accountA.response.status === 403 &&
      accountB.response.status >= 200 &&
      accountB.response.status < 300) ||
    (accountB.response.status === 403 &&
      accountA.response.status >= 200 &&
      accountA.response.status < 300)
  ) {
    return "403-vs-200";
  }
  if (
    accountA.response.status >= 200 &&
    accountA.response.status < 300 &&
    accountB.response.status >= 200 &&
    accountB.response.status < 300
  ) {
    return responseHash(accountA) === responseHash(accountB)
      ? "same-response"
      : "different-but-200";
  }
  return responseHash(accountA) === responseHash(accountB)
    ? "same-response"
    : "different-but-200";
}

function suspicionScore(bucket: HarDiffBucket): number {
  if (bucket === "same-response") return 80;
  if (bucket === "different-but-200") return 55;
  if (bucket === "403-vs-200") return 45;
  return 30;
}
