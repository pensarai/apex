import type {
  ThreatModelResult,
  ApplicationContext,
  AttackPath,
  Component,
  DataFlow,
  DeploymentContext,
  SecurityControlsResult,
  TrustBoundary,
} from "./types";

// ---------------------------------------------------------------------------
// Markdown serializer
// ---------------------------------------------------------------------------

const SEVERITY_LABELS: Record<string, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};

/**
 * Serialize a threat model result to a structured Markdown document
 * optimized for LLM consumption via `read_file` and `grep`.
 */
export function serializeThreatModelToMarkdown(
  model: ThreatModelResult,
): string {
  const sections: string[] = [];

  sections.push(renderHeader(model));
  sections.push(renderApplicationContextSection(model.applicationContext));
  sections.push(renderDeploymentSection(model.deployment));
  sections.push(
    renderComponentsSection(model.architecture.components),
  );
  sections.push(
    renderTrustBoundariesSection(
      model.architecture.trustBoundaries,
      model.architecture.components,
    ),
  );
  sections.push(renderDataFlowsSection(model.architecture.dataFlows));
  sections.push(renderSecurityControlsSection(model.securityControls));
  sections.push(renderAttackPathsSection(model.attackPaths));
  sections.push(renderSummarySection(model));

  return sections.join("\n\n");
}

// ---------------------------------------------------------------------------
// Section renderers
// ---------------------------------------------------------------------------

function renderHeader(model: ThreatModelResult): string {
  const m = model.metadata;
  const lines: string[] = [
    "# Threat Model",
    "",
    `**Generated:** ${m.generatedAt}`,
    `**Codebase:** ${m.target}`,
  ];

  if (m.repoType) {
    lines.push(`**Repo Type:** ${m.repoType}`);
  }
  if (m.packageManager) {
    lines.push(`**Package Manager:** ${m.packageManager}`);
  }

  lines.push("");
  lines.push("---");

  return lines.join("\n");
}

function renderApplicationContextSection(ctx: ApplicationContext): string {
  const lines: string[] = ["## Application Context"];

  // Identity
  lines.push("");
  lines.push("### Identity");
  lines.push(`- **Type:** ${capitalize(ctx.identity.type)}`);
  lines.push(`- **Domain:** ${ctx.identity.domain}`);
  lines.push(`- **Description:** ${ctx.identity.description}`);
  lines.push("- **Users:**");
  for (const user of ctx.identity.users) {
    lines.push(`  - ${user}`);
  }
  lines.push("- **Core Capabilities:**");
  for (const cap of ctx.identity.coreCapabilities) {
    lines.push(`  - ${cap}`);
  }

  // Features table
  lines.push("");
  lines.push("### Features & Capabilities");
  lines.push("");
  lines.push(
    "| Name | Security Relevance | Privileged Operations | Data Handled |",
  );
  lines.push(
    "|------|-------------------|----------------------|--------------|",
  );
  for (const f of ctx.features) {
    lines.push(
      `| **${f.name}** — ${f.description} | ${f.securityRelevance} | ${f.privilegedOperations.join("; ") || "\u2014"} | ${f.dataHandled.join("; ") || "\u2014"} |`,
    );
  }

  // Application trust boundaries
  lines.push("");
  lines.push("### Trust Boundaries (Application-Specific)");
  for (const tb of ctx.trustBoundaries) {
    lines.push("");
    lines.push(`#### ${tb.name}`);
    lines.push(`${tb.description}`);
    lines.push("- **Input Sources:**");
    for (const src of tb.inputSources) {
      lines.push(`  - ${src}`);
    }
    lines.push(`- **Crosses To:** ${tb.crossesTo}`);
  }

  // Attacker profiles
  lines.push("");
  lines.push("### Attacker Profiles");
  for (const ap of ctx.attackerProfiles) {
    lines.push("");
    lines.push(`#### ${ap.name}`);
    lines.push(`${ap.description}`);
    lines.push(`- **Skill Level:** ${capitalize(ap.skillLevel)}`);
    lines.push("- **Controls:**");
    for (const ctrl of ap.controls) {
      lines.push(`  - ${ctrl}`);
    }
    lines.push("- **Goals:**");
    for (const goal of ap.goals) {
      lines.push(`  - ${goal}`);
    }
  }

  return lines.join("\n");
}

function renderDeploymentSection(d: DeploymentContext): string {
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
    if (d.containers.runtime) {
      lines.push(`- **Runtime:** ${d.containers.runtime}`);
    }
    if (d.containers.orchestration) {
      lines.push(`- **Orchestration:** ${d.containers.orchestration}`);
    }
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
  if (d.iac.length > 0) {
    lines.push("");
    lines.push("### Infrastructure as Code");
    lines.push("| Tool | Config Path |");
    lines.push("|------|------------|");
    for (const entry of d.iac) {
      lines.push(`| ${entry.tool} | ${entry.configPath} |`);
    }
  }

  // CI/CD
  if (d.cicd.length > 0) {
    lines.push("");
    lines.push("### CI/CD");
    for (const ci of d.cicd) {
      lines.push(`- ${ci}`);
    }
  }

  // Databases
  if (d.databases.length > 0) {
    lines.push("");
    lines.push("### Databases");
    for (const db of d.databases) {
      const ver = db.version ? ` ${db.version}` : "";
      lines.push(`- ${db.type}${ver}`);
    }
  }

  // Message Queues
  if (d.messageQueues.length > 0) {
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
  if (d.environmentFiles.length > 0) {
    lines.push("");
    lines.push("### Environment Files");
    for (const ef of d.environmentFiles) {
      lines.push(`- \`${ef}\``);
    }
  }

  return lines.join("\n");
}

function renderComponentsSection(components: Component[]): string {
  const lines: string[] = ["## System Components", ""];
  lines.push("| ID | Name | Type | Technology | Trust Boundary |");
  lines.push("|----|------|------|------------|----------------|");
  for (const c of components) {
    lines.push(
      `| ${c.id} | ${c.name} | ${formatType(c.type)} | ${c.technology} | ${c.trustBoundary} |`,
    );
  }
  return lines.join("\n");
}

function renderTrustBoundariesSection(
  trustBoundaries: TrustBoundary[],
  components: Component[],
): string {
  const lines: string[] = ["## Trust Boundaries"];

  const componentMap = new Map(components.map((c) => [c.id, c]));

  for (const tb of trustBoundaries) {
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
    "| Source | Destination | Protocol | Classification | Authenticated | Encrypted |",
  );
  lines.push(
    "|--------|-------------|----------|----------------|---------------|-----------|",
  );
  for (const df of dataFlows) {
    lines.push(
      `| ${df.from} | ${df.to} | ${df.protocol} | ${capitalize(df.dataClassification)} | ${df.authenticated ? "Yes" : "No"} | ${df.encrypted ? "Yes" : "No"} |`,
    );
  }
  return lines.join("\n");
}

function renderSecurityControlsSection(sc: SecurityControlsResult): string {
  const lines: string[] = ["## Security Controls"];

  for (let i = 0; i < sc.controls.length; i++) {
    const ctrl = sc.controls[i]!;
    lines.push("");
    lines.push(`### SC-${String(i + 1).padStart(2, "0")}: ${ctrl.name}`);
    lines.push(`- **Type:** ${formatType(ctrl.type)}`);
    lines.push(`- **Effectiveness:** ${capitalize(ctrl.effectiveness)}`);
    lines.push(`- **Scope:** ${ctrl.scope}`);
    lines.push(`- **Implementation:** ${ctrl.implementation}`);
    if (ctrl.gaps) {
      lines.push(`- **Gaps:** ${ctrl.gaps}`);
    }
  }

  // Authentication mechanism
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

  // Authorization model
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

function renderAttackPathsSection(attackPaths: AttackPath[]): string {
  const lines: string[] = ["## Attack Paths"];

  for (const ap of attackPaths) {
    const sevLabel = SEVERITY_LABELS[ap.severity] ?? ap.severity;

    lines.push("");
    lines.push(`### ${ap.id}: ${ap.title} [${sevLabel}]`);
    lines.push("");
    lines.push(`**Attacker Profile:** ${ap.attackerProfile}`);
    lines.push(`**Entry Point:** ${ap.entryPoint}`);
    lines.push(`**Severity:** ${capitalize(ap.severity)}`);
    lines.push(`**Affected Features:** ${ap.affectedFeatures.join(", ")}`);

    // Mechanism (numbered steps)
    lines.push("");
    lines.push("**Mechanism:**");
    for (let i = 0; i < ap.mechanism.length; i++) {
      lines.push(`${i + 1}. ${ap.mechanism[i]}`);
    }

    // Impact
    lines.push("");
    lines.push(`**Impact:** ${ap.impact}`);

    // Preconditions
    lines.push("");
    lines.push("#### Preconditions");
    if (ap.preconditions.length === 0) {
      lines.push("- None");
    } else {
      for (const pre of ap.preconditions) {
        lines.push(`- ${pre}`);
      }
    }

    // Existing Controls
    lines.push("");
    lines.push("#### Existing Controls");
    if (ap.existingControls.length === 0) {
      lines.push("- None identified");
    } else {
      for (const ctrl of ap.existingControls) {
        lines.push(`- ${ctrl}`);
      }
    }

    // Control Gaps
    lines.push("");
    lines.push("#### Control Gaps");
    if (ap.controlGaps.length === 0) {
      lines.push("- None identified");
    } else {
      for (const gap of ap.controlGaps) {
        lines.push(`- ${gap}`);
      }
    }

    // Pentest Guidance
    lines.push("");
    lines.push("#### Pentest Guidance");

    lines.push("");
    lines.push("**Objectives:**");
    for (let i = 0; i < ap.pentestGuidance.objectives.length; i++) {
      lines.push(`${i + 1}. ${ap.pentestGuidance.objectives[i]}`);
    }

    if (ap.pentestGuidance.techniques.length > 0) {
      lines.push("");
      lines.push("**Techniques:**");
      for (const tech of ap.pentestGuidance.techniques) {
        lines.push(`- ${tech}`);
      }
    }

    if (ap.pentestGuidance.deploymentConsiderations.length > 0) {
      lines.push("");
      lines.push("**Deployment Considerations:**");
      for (const dc of ap.pentestGuidance.deploymentConsiderations) {
        lines.push(`- ${dc}`);
      }
    }

    if (ap.pentestGuidance.prerequisites.length > 0) {
      lines.push("");
      lines.push("**Prerequisites:**");
      for (const pr of ap.pentestGuidance.prerequisites) {
        lines.push(`- ${pr}`);
      }
    }
  }

  return lines.join("\n");
}

function renderSummarySection(model: ThreatModelResult): string {
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
    `| Total Attack Paths | ${s.totalAttackPaths} |`,
    "",
    "### Attack Paths by Severity",
    "",
    "| Severity | Count |",
    "|----------|-------|",
    `| Critical | ${s.bySeverity.critical} |`,
    `| High | ${s.bySeverity.high} |`,
    `| Medium | ${s.bySeverity.medium} |`,
    `| Low | ${s.bySeverity.low} |`,
  ];

  if (s.topRisks.length > 0) {
    lines.push("");
    lines.push("### Top Risks");
    for (const risk of s.topRisks) {
      lines.push(`- ${risk}`);
    }
  }

  return lines.join("\n");
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
