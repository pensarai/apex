import type {
  STRIDEThreatModel,
  Component,
  DataFlow,
  SecurityControl,
  Threat,
} from "./types";

// ---------------------------------------------------------------------------
// Markdown serializer
// ---------------------------------------------------------------------------

const STRIDE_CATEGORY_LABELS: Record<string, string> = {
  spoofing: "SPOOFING",
  tampering: "TAMPERING",
  repudiation: "REPUDIATION",
  information_disclosure: "INFORMATION_DISCLOSURE",
  denial_of_service: "DENIAL_OF_SERVICE",
  elevation_of_privilege: "ELEVATION_OF_PRIVILEGE",
};

const RISK_LABELS: Record<string, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  negligible: "NEGLIGIBLE",
};

/**
 * Serialize a STRIDE threat model to a structured markdown document
 * optimized for LLM agent consumption via `read_file` and `grep`.
 */
export function serializeThreatModelToMarkdown(
  model: STRIDEThreatModel,
): string {
  const sections: string[] = [];

  // =========================================================================
  // Header
  // =========================================================================

  sections.push(`# STRIDE Threat Model

**Generated:** ${model.metadata.generatedAt}
**Codebase:** ${model.metadata.codebasePath}
**Repo Type:** ${model.metadata.repoType}
**Package Manager:** ${model.metadata.packageManager}

---`);

  // =========================================================================
  // Deployment Model
  // =========================================================================

  sections.push(renderDeploymentSection(model));

  // =========================================================================
  // System Components
  // =========================================================================

  sections.push(renderComponentsSection(model.components));

  // =========================================================================
  // Trust Boundaries
  // =========================================================================

  sections.push(renderTrustBoundariesSection(model));

  // =========================================================================
  // Data Flows
  // =========================================================================

  sections.push(renderDataFlowsSection(model.dataFlows));

  // =========================================================================
  // Security Controls
  // =========================================================================

  sections.push(renderSecurityControlsSection(model));

  // =========================================================================
  // STRIDE Threats
  // =========================================================================

  sections.push(renderThreatsSection(model.threats, model.components));

  // =========================================================================
  // Summary
  // =========================================================================

  sections.push(renderSummarySection(model));

  return sections.join("\n\n");
}

// ---------------------------------------------------------------------------
// Section renderers
// ---------------------------------------------------------------------------

function renderDeploymentSection(model: STRIDEThreatModel): string {
  const d = model.deployment;
  const lines: string[] = ["## Deployment Model"];

  // Cloud
  if (d.cloud) {
    lines.push("");
    lines.push("### Cloud");
    if (d.cloud.provider) {
      const region = d.cloud.region ? ` (${d.cloud.region})` : "";
      lines.push(`- **Provider:** ${d.cloud.provider}${region}`);
    }
    if (d.cloud.services && d.cloud.services.length > 0) {
      lines.push(`- **Services:** ${d.cloud.services.join(", ")}`);
    }
  }

  // Containers
  if (d.containers) {
    lines.push("");
    lines.push("### Containers");
    if (d.containers.runtime)
      lines.push(`- **Runtime:** ${d.containers.runtime}`);
    if (d.containers.orchestration)
      lines.push(`- **Orchestration:** ${d.containers.orchestration}`);
    lines.push(
      `- **Dockerfile:** ${d.containers.hasDockerfile ? "Yes" : "No"}`,
    );
    lines.push(
      `- **Docker Compose:** ${d.containers.hasDockerCompose ? "Yes" : "No"}`,
    );
    lines.push(
      `- **Kubernetes:** ${d.containers.hasKubernetes ? "Yes" : "No"}`,
    );
  }

  // Infrastructure as Code
  if (d.iac && d.iac.length > 0) {
    lines.push("");
    lines.push("### Infrastructure as Code");
    lines.push("| Tool | Config Path |");
    lines.push("|------|------------|");
    for (const entry of d.iac) {
      lines.push(`| ${entry.tool} | ${entry.configPath} |`);
    }
  }

  // CI/CD
  if (d.cicd && d.cicd.length > 0) {
    lines.push("");
    lines.push("### CI/CD");
    for (const ci of d.cicd) {
      lines.push(`- ${ci}`);
    }
  }

  // Databases
  if (d.databases && d.databases.length > 0) {
    lines.push("");
    lines.push("### Databases");
    for (const db of d.databases) {
      const ver = db.version ? ` ${db.version}` : "";
      lines.push(`- ${db.type}${ver}`);
    }
  }

  // Message Queues
  if (d.messageQueues && d.messageQueues.length > 0) {
    lines.push("");
    lines.push("### Message Queues");
    for (const mq of d.messageQueues) {
      lines.push(`- ${mq}`);
    }
  }

  // Reverse Proxy
  if (d.reverseProxy) {
    lines.push("");
    lines.push("### Reverse Proxy");
    lines.push(`- ${d.reverseProxy}`);
  }

  // Environment Files
  if (d.environmentFiles && d.environmentFiles.length > 0) {
    lines.push("");
    lines.push("### Environment Files");
    for (const ef of d.environmentFiles) {
      lines.push(`- ${ef}`);
    }
  }

  return lines.join("\n");
}

function renderComponentsSection(components: Component[]): string {
  const lines: string[] = ["## System Components", ""];
  lines.push(
    "| ID | Name | Type | Technology | Trust Boundary |",
  );
  lines.push(
    "|----|------|------|------------|----------------|",
  );
  for (const c of components) {
    lines.push(
      `| ${c.id} | ${c.name} | ${formatType(c.type)} | ${c.technology} | ${c.trustBoundary} |`,
    );
  }
  return lines.join("\n");
}

function renderTrustBoundariesSection(model: STRIDEThreatModel): string {
  const lines: string[] = ["## Trust Boundaries"];

  const componentMap = new Map(model.components.map((c) => [c.id, c]));

  for (const tb of model.trustBoundaries) {
    lines.push("");
    const levelLabel = formatTrustLevel(tb.level);
    lines.push(`### ${tb.name} (${tb.id})`);
    lines.push(`**Level:** ${levelLabel}`);
    const componentNames = tb.componentIds
      .map((id) => {
        const comp = componentMap.get(id);
        return comp ? `${comp.id} (${comp.name})` : id;
      })
      .join(", ");
    lines.push(`**Components:** ${componentNames}`);
  }

  return lines.join("\n");
}

function renderDataFlowsSection(dataFlows: DataFlow[]): string {
  const lines: string[] = ["## Data Flows", ""];
  lines.push(
    "| ID | From | To | Protocol | Data Classification | Authenticated | Encrypted |",
  );
  lines.push(
    "|----|------|----|----------|-------------------|---------------|-----------|",
  );
  for (const df of dataFlows) {
    lines.push(
      `| ${df.id} | ${df.from} | ${df.to} | ${df.protocol} | ${capitalize(df.dataClassification)} | ${df.authenticated ? "Yes" : "No"} | ${df.encrypted ? "Yes" : "No"} |`,
    );
  }
  return lines.join("\n");
}

function renderSecurityControlsSection(model: STRIDEThreatModel): string {
  const lines: string[] = ["## Security Controls"];
  const sc = model.securityControls;

  for (let i = 0; i < sc.controls.length; i++) {
    const ctrl = sc.controls[i]!;
    lines.push("");
    lines.push(`### SC-${i + 1}: ${ctrl.name}`);
    lines.push(`- **Type:** ${ctrl.type}`);
    lines.push(`- **Effectiveness:** ${capitalize(ctrl.effectiveness)}`);
    lines.push(`- **Scope:** ${ctrl.scope}`);
    if (ctrl.file) {
      const loc = ctrl.line ? `${ctrl.file}:${ctrl.line}` : ctrl.file;
      lines.push(`- **File:** ${loc}`);
    }
    lines.push(`- **Implementation:** ${ctrl.implementation}`);
    if (ctrl.gaps) {
      lines.push(`- **Gaps:** ${ctrl.gaps}`);
    }
  }

  // Authentication Mechanism
  if (sc.authenticationMechanism) {
    const auth = sc.authenticationMechanism;
    lines.push("");
    lines.push("### Authentication Mechanism");
    lines.push(`- **Type:** ${auth.type}`);
    lines.push(`- **Implementation:** ${auth.implementation}`);
    lines.push(`- **Session Storage:** ${auth.sessionStorage}`);
    if (auth.mfa) {
      lines.push(`- **MFA:** ${auth.mfa}`);
    }
  }

  // Authorization Model
  if (sc.authorizationModel) {
    const authz = sc.authorizationModel;
    lines.push("");
    lines.push("### Authorization Model");
    lines.push(`- **Type:** ${authz.type}`);
    lines.push(`- **Implementation:** ${authz.implementation}`);
    if (authz.roles && authz.roles.length > 0) {
      lines.push(`- **Roles:** ${authz.roles.join(", ")}`);
    }
  }

  return lines.join("\n");
}

function renderThreatsSection(
  threats: Threat[],
  components: Component[],
): string {
  const lines: string[] = ["## STRIDE Threats"];
  const componentMap = new Map(components.map((c) => [c.id, c]));

  for (const t of threats) {
    const catLabel = STRIDE_CATEGORY_LABELS[t.category] ?? t.category;
    const riskLabel = RISK_LABELS[t.residualRisk] ?? t.residualRisk;
    const comp = componentMap.get(t.targetComponent);
    const compLabel = comp
      ? `${comp.id} (${comp.name})`
      : t.targetComponent;

    lines.push("");
    lines.push(`### ${t.id}: ${t.title} [${catLabel}] [${riskLabel}]`);
    lines.push("");
    lines.push(`**Target Component:** ${compLabel}`);
    if (t.affectedDataFlow) {
      lines.push(`**Affected Data Flow:** ${t.affectedDataFlow}`);
    }
    lines.push(`**Residual Risk:** ${capitalize(t.residualRisk)}`);
    lines.push("");
    lines.push(`${t.description}`);

    // Preconditions
    lines.push("");
    lines.push("#### Preconditions");
    for (const pre of t.preconditions) {
      lines.push(`- ${pre}`);
    }

    // Attack Vectors
    lines.push("");
    lines.push("#### Attack Vectors");
    lines.push("| Endpoint | Method | Parameter | Technique |");
    lines.push("|----------|--------|-----------|-----------|");
    for (const av of t.attackVectors) {
      lines.push(
        `| ${av.endpoint} | ${av.method} | ${av.parameter || "—"} | ${av.technique} |`,
      );
    }

    // Tool suggestions (collect from all attack vectors)
    const allTools = t.attackVectors
      .flatMap((av) => av.toolSuggestions)
      .filter((v, i, a) => a.indexOf(v) === i);
    if (allTools.length > 0) {
      lines.push("");
      lines.push(`**Suggested Tools:** ${allTools.join(", ")}`);
    }

    // Existing Mitigations
    lines.push("");
    lines.push("#### Existing Mitigations");
    if (t.existingMitigations.length === 0) {
      lines.push("- None identified");
    } else {
      for (const m of t.existingMitigations) {
        lines.push(`- ${m}`);
      }
    }

    // Pentest Guidance
    lines.push("");
    lines.push("#### Pentest Guidance");

    lines.push("**Objectives:**");
    for (let i = 0; i < t.pentestGuidance.objectives.length; i++) {
      lines.push(`${i + 1}. ${t.pentestGuidance.objectives[i]}`);
    }

    if (t.pentestGuidance.deploymentConsiderations.length > 0) {
      lines.push("");
      lines.push("**Deployment Considerations:**");
      for (const dc of t.pentestGuidance.deploymentConsiderations) {
        lines.push(`- ${dc}`);
      }
    }

    if (t.pentestGuidance.prerequisites.length > 0) {
      lines.push("");
      lines.push("**Prerequisites:**");
      for (const pr of t.pentestGuidance.prerequisites) {
        lines.push(`- ${pr}`);
      }
    }
  }

  return lines.join("\n");
}

function renderSummarySection(model: STRIDEThreatModel): string {
  const s = model.summary;
  const lines: string[] = [
    "---",
    "",
    "## Summary",
    "",
    "| Metric | Count |",
    "|--------|-------|",
    `| Total Components | ${s.totalComponents} |`,
    `| Total Data Flows | ${s.totalDataFlows} |`,
    `| Total Threats | ${s.totalThreats} |`,
    "",
    "### Threats by STRIDE Category",
    "| Category | Count |",
    "|----------|-------|",
    `| Spoofing | ${s.threatsByCategory.spoofing} |`,
    `| Tampering | ${s.threatsByCategory.tampering} |`,
    `| Repudiation | ${s.threatsByCategory.repudiation} |`,
    `| Information Disclosure | ${s.threatsByCategory.information_disclosure} |`,
    `| Denial of Service | ${s.threatsByCategory.denial_of_service} |`,
    `| Elevation of Privilege | ${s.threatsByCategory.elevation_of_privilege} |`,
    "",
    "### Threats by Residual Risk",
    "| Risk Level | Count |",
    "|------------|-------|",
    `| Critical | ${s.threatsByRisk.critical} |`,
    `| High | ${s.threatsByRisk.high} |`,
    `| Medium | ${s.threatsByRisk.medium} |`,
    `| Low | ${s.threatsByRisk.low} |`,
    `| Negligible | ${s.threatsByRisk.negligible} |`,
  ];

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// JSON serializer
// ---------------------------------------------------------------------------

/**
 * Serialize a STRIDE threat model to pretty-printed JSON for programmatic use.
 */
export function serializeThreatModelToJson(
  model: STRIDEThreatModel,
): string {
  return JSON.stringify(model, null, 2);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function formatType(type: string): string {
  return type
    .split("_")
    .map((w) => capitalize(w))
    .join(" ");
}

function formatTrustLevel(level: string): string {
  switch (level) {
    case "external":
      return "External/Internet";
    case "dmz":
      return "DMZ/Edge";
    case "internal":
      return "Internal/Application";
    case "data":
      return "Data Tier";
    default:
      return capitalize(level);
  }
}
