import { existsSync, readFileSync } from "node:fs";
import { basename, resolve } from "node:path";

type AdversarialObservation = {
  source: string;
  category: string;
  evidence: string;
  risk: string;
  recommendedHandling: string;
  actionConsistency: string;
  relatedAction?: string;
};

type TraceRecord = {
  type?: string;
  adversarialObservations?: AdversarialObservation[];
};

const defaultTrace = new URL("./sample-trace.jsonl", import.meta.url).pathname;
const tracePath = resolve(process.argv[2] ?? defaultTrace);

function readJsonl(path: string): TraceRecord[] {
  if (!existsSync(path)) {
    throw new Error(`Trace file not found: ${path}`);
  }

  return readFileSync(path, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line) as TraceRecord;
      } catch (error) {
        throw new Error(
          `Invalid JSONL on line ${index + 1}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    });
}

function increment(map: Map<string, number>, key: string) {
  map.set(key, (map.get(key) ?? 0) + 1);
}

const records = readJsonl(tracePath);
const observations = records.flatMap((record) =>
  record.type === "checkpoint" ? (record.adversarialObservations ?? []) : [],
);

const byConsistency = new Map<string, number>();
const byCategory = new Map<string, number>();
const bySource = new Map<string, number>();
const highRiskCompliances: AdversarialObservation[] = [];

for (const observation of observations) {
  increment(byConsistency, observation.actionConsistency);
  increment(byCategory, observation.category);
  increment(bySource, observation.source);

  if (
    ["high", "critical"].includes(observation.risk) &&
    observation.actionConsistency === "detected_but_complied"
  ) {
    highRiskCompliances.push(observation);
  }
}

console.log(`Trace: ${basename(tracePath)}`);
console.log(`Checkpoint adversarial observations: ${observations.length}`);

if (observations.length === 0) {
  console.log("No adversarial observations were recorded.");
  process.exit(0);
}

console.log("\nAction consistency");
for (const [key, value] of [...byConsistency.entries()].sort()) {
  console.log(`- ${key}: ${value}`);
}

console.log("\nCategories");
for (const [key, value] of [...byCategory.entries()].sort()) {
  console.log(`- ${key}: ${value}`);
}

console.log("\nSources");
for (const [key, value] of [...bySource.entries()].sort()) {
  console.log(`- ${key}: ${value}`);
}

if (highRiskCompliances.length > 0) {
  console.log("\nHigh-risk detected-but-complied observations");
  for (const observation of highRiskCompliances) {
    console.log(`- ${observation.category}: ${observation.evidence}`);
    if (observation.relatedAction) {
      console.log(`  related action: ${observation.relatedAction}`);
    }
  }
} else {
  console.log("\nNo high-risk detected-but-complied observations.");
}
