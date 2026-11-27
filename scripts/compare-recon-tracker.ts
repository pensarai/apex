import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { loadTopology } from "../src/core/agents/offSecAgent/tools/topologyRecords";
import { assessTopology } from "./recon-tracker/assess";
import { csv, type ScopeItem } from "./recon-tracker/scope";

const { values } = parseArgs({
  options: { baseline: { type: "string" }, tracker: { type: "string" } },
  strict: true,
});
if (!values.baseline)
  throw new Error(
    "Usage: --baseline <run-directory> [--tracker <run-directory>]",
  );
const read = (dir: string, file: string) =>
  JSON.parse(readFileSync(join(dir, file), "utf8"));
const escapeHtml = (value: unknown) =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
const runs = [values.baseline, values.tracker]
  .filter((dir): dir is string => Boolean(dir))
  .map((dir) => {
    dir = resolve(dir);
    const inputs = read(dir, "inputs.json");
    const scope = read(dir, "scope.json") as { items: ScopeItem[] };
    const finished = existsSync(join(dir, "result.json"));
    const result = finished
      ? read(dir, "result.json")
      : { ...read(dir, "progress.json"), status: "running" };
    const eventsPath = join(dir, "events.jsonl");
    const events = existsSync(eventsPath)
      ? readFileSync(eventsPath, "utf8")
          .trim()
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line))
      : [];
    const httpCalls = new Map(
      events
        .filter(
          (event) =>
            event.event === "tool-call-complete" &&
            event.data.toolName === "http_request",
        )
        .map((event) => [event.data.toolCallId, event.data.args]),
    );
    const httpResults = events
      .filter(
        (event) =>
          event.event === "tool-result" &&
          event.data.toolName === "http_request",
      )
      .flatMap((event) => {
        const result =
          typeof event.data.result === "string"
            ? JSON.parse(event.data.result)
            : event.data.result;
        const args = httpCalls.get(event.data.toolCallId);
        const rejected =
          /Scope violation:|Destructive action|Conflicting timeout values:|ToolPolicyDenied/i.test(
            result?.error ?? "",
          );
        return args && typeof result?.status === "number" && !rejected
          ? [{ url: args.url, status: result.status }]
          : [];
      });
    const inScope = new Set(scope.items.map((item) => item.domain));
    const httpDomains = new Set(
      httpResults
        .map((event) => new URL(event.url).hostname)
        .filter((host) => inScope.has(host)),
    );
    const httpRespondingDomains = new Set(
      httpResults
        .filter((event) => event.status > 0)
        .map((event) => new URL(event.url).hostname)
        .filter((host) => inScope.has(host)),
    );
    const topology = finished
      ? read(dir, "topology.json")
      : loadTopology(inputs.session.rootPath);
    const trackerPath = join(
      finished ? dir : inputs.session.rootPath,
      "coverage.csv",
    );
    const assessment = assessTopology(
      scope.items,
      topology,
      existsSync(trackerPath) ? readFileSync(trackerPath, "utf8") : undefined,
    );
    writeFileSync(
      join(dir, "assessment.json"),
      JSON.stringify(assessment, null, 2),
    );
    writeFileSync(
      join(dir, "domain-evidence.csv"),
      csv([
        [
          "id",
          "domain",
          "component_ids",
          "threat_ids",
          "record_ids",
          "retired_record_ids",
        ],
        ...assessment.rows.map((r) => [
          r.id,
          r.domain,
          r.componentIds.join(";"),
          r.threatIds.join(";"),
          r.referencedRecordIds.join(";"),
          r.retiredRecordIds.join(";"),
        ]),
      ]),
    );
    const componentHtml = topology.components
      .map((c: Record<string, unknown>) => {
        const threats = topology.threats.filter(
          (t: Record<string, unknown>) => t.componentId === c.id,
        );
        return `<details><summary>${escapeHtml(c.name)} — ${threats.length} threats</summary><pre>${escapeHtml(JSON.stringify(c, null, 2))}</pre>${threats.map((t: Record<string, unknown>) => `<h3>${escapeHtml(t.title)}</h3><pre>${escapeHtml(JSON.stringify(t, null, 2))}</pre>`).join("")}</details>`;
      })
      .join("");
    const retiredHtml = topology.retired
      .map(
        ({ kind, record }: { kind: string; record: Record<string, unknown> }) =>
          `<details><summary>${escapeHtml(kind)}: ${escapeHtml(record.name)}</summary><pre>${escapeHtml(JSON.stringify(record, null, 2))}</pre></details>`,
      )
      .join("");
    const html = `<!doctype html><meta charset="utf-8"><title>Recon ${escapeHtml(inputs.arm)} review</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 24px;color:#17212b}table{border-collapse:collapse;width:100%}td,th{padding:9px;border-bottom:1px solid #ccd;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:16px;font-size:13px}details{border:1px solid #ccd;margin:12px 0;padding:14px}summary{cursor:pointer;font-weight:650}.note{background:#fff4d9;padding:16px}</style><h1>Recon ${escapeHtml(inputs.arm)} review</h1><p>${escapeHtml(result.status)} · ${(result.elapsedSeconds / 60).toFixed(1)} minutes · $${result.estimatedUsd.toFixed(2)} estimated · ${scope.items.length} domains</p><p class="note">${assessment.caveats.map(escapeHtml).join(" ")}</p><h2>Coverage</h2><p>${assessment.endpointMappedDomains} domains explicitly mapped to component endpoints; ${assessment.recordReferencedDomains} referenced in active records; ${assessment.anyRecordReferencedDomains} referenced including retired records; ${assessment.domainsMappedToThreats} mapped to a component with threats.</p><details><summary>Per-domain coverage (${scope.items.length})</summary><table><tr><th>Domain</th><th>Components</th><th>Threats</th><th>Retired records</th></tr>${assessment.rows.map((r) => `<tr><td>${escapeHtml(r.domain)}</td><td>${escapeHtml(r.componentIds.join(", "))}</td><td>${r.threatIds.length}</td><td>${escapeHtml(r.retiredRecordIds.join(", "))}</td></tr>`).join("")}</table></details><h2>Threat models</h2>${componentHtml}<h2>Retired dispositions</h2>${retiredHtml}<h2>Tracker checks</h2><pre>${escapeHtml(JSON.stringify(assessment.trackerCheck ?? "No seeded tracker in this arm", null, 2))}</pre><h2>Run metadata</h2><pre>${escapeHtml(JSON.stringify({ inputs, result }, null, 2))}</pre>`;
    writeFileSync(join(dir, "review.html"), html);
    return {
      directory: dir,
      inputs,
      result,
      coverage: {
        total: scope.items.length,
        structuredHttpAttemptDomains: httpDomains.size,
        structuredHttpResponseDomains: httpRespondingDomains.size,
        endpointMapped: assessment.endpointMappedDomains,
        recordReferenced: assessment.recordReferencedDomains,
        retiredReferenced: assessment.retiredReferencedDomains,
        anyRecordReferenced: assessment.anyRecordReferencedDomains,
        mappedToThreats: assessment.domainsMappedToThreats,
        componentsWithoutThreats: assessment.componentsWithoutThreats,
        componentsWithMultipleThreats: assessment.componentsWithMultipleThreats,
        trackerErrors: assessment.trackerCheck?.errors,
        trackerPending: assessment.trackerCheck?.pending,
      },
    };
  });
if (runs.length === 2) {
  for (const key of [
    "sourceSha256",
    "model",
    "commit",
    "toolProtocol",
    "toolPolicy",
    "startMode",
  ])
    if (runs[0].inputs[key] !== runs[1].inputs[key])
      throw new Error(`Unmatched comparison: ${key}`);
}
console.log(
  JSON.stringify(
    runs.map(({ inputs, ...run }) => ({ arm: inputs.arm, ...run })),
    null,
    2,
  ),
);
