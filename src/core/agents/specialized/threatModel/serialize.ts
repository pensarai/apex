import type {
  ThreatModel,
  Component,
  DataFlow,
  AttackPath,
  ApplicationContext,
  SecurityControlsResult,
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
 * Serialize a threat model to a structured markdown document
 * optimized for LLM agent consumption via `read_file` and `grep`.
 */
export function serializeThreatModelToMarkdown(model: ThreatModel): string {
  const sections: string[] = [];

  // =========================================================================
  // Header
  // =========================================================================

  sections.push(`# Threat Model

**Generated:** ${model.metadata.generatedAt}
**Codebase:** ${model.metadata.codebasePath}
**Repo Type:** ${model.metadata.repoType}
**Package Manager:** ${model.metadata.packageManager}

---`);

  // =========================================================================
  // Application Context
  // =========================================================================

  sections.push(renderApplicationContextSection(model.applicationContext));

  // =========================================================================
  // Deployment Model
  // =========================================================================

  sections.push(renderDeploymentSection(model));

  // =========================================================================
  // System Components
  // =========================================================================

  sections.push(renderComponentsSection(model.components));

  // =========================================================================
  // Trust Boundaries (system-level)
  // =========================================================================

  sections.push(renderTrustBoundariesSection(model));

  // =========================================================================
  // Data Flows
  // =========================================================================

  sections.push(renderDataFlowsSection(model.dataFlows));

  // =========================================================================
  // Security Controls
  // =========================================================================

  sections.push(renderSecurityControlsSection(model.securityControls));

  // =========================================================================
  // Attack Paths
  // =========================================================================

  sections.push(renderAttackPathsSection(model.attackPaths));

  // =========================================================================
  // Summary
  // =========================================================================

  sections.push(renderSummarySection(model));

  return sections.join("\n\n");
}

// ---------------------------------------------------------------------------
// Section renderers
// ---------------------------------------------------------------------------

function renderApplicationContextSection(ctx: ApplicationContext): string {
  const lines: string[] = ["## Application Context"];

  // Identity
  lines.push("");
  lines.push("### Identity");
  lines.push(`- **Type:** ${capitalize(ctx.identity.type)}`);
  lines.push(`- **Domain:** ${ctx.identity.domain}`);
  lines.push(`- **Description:** ${ctx.identity.description}`);
  lines.push(`- **Users:** ${ctx.identity.users.join(", ")}`);
  lines.push(
    `- **Core Capabilities:** ${ctx.identity.coreCapabilities.join(", ")}`,
  );

  // Features & Capabilities
  lines.push("");
  lines.push("### Features & Capabilities");
  lines.push("");
  lines.push(
    "| Feature | Security Relevance | Privileged Operations | Data Handled |",
  );
  lines.push(
    "|---------|-------------------|----------------------|--------------|",
  );
  for (const f of ctx.features) {
    lines.push(
      `| **${f.name}** — ${f.description} | ${f.securityRelevance} | ${f.privilegedOperations.join("; ") || "—"} | ${f.dataHandled.join("; ") || "—"} |`,
    );
  }

  // Application-Specific Trust Boundaries
  lines.push("");
  lines.push("### Trust Boundaries (Application-Specific)");
  for (const tb of ctx.trustBoundaries) {
    lines.push("");
    lines.push(`#### ${tb.name}`);
    lines.push(`${tb.description}`);
    lines.push(`- **Input Sources:** ${tb.inputSources.join(", ")}`);
    lines.push(`- **Crosses To:** ${tb.crossesTo}`);
  }

  // Attacker Profiles
  lines.push("");
  lines.push("### Attacker Profiles");
  for (const ap of ctx.attackerProfiles) {
    lines.push("");
    lines.push(`#### ${ap.name}`);
    lines.push(`${ap.description}`);
    lines.push(`- **Skill Level:** ${capitalize(ap.skillLevel)}`);
    lines.push(`- **Controls:** ${ap.controls.join(", ")}`);
    lines.push(`- **Goals:** ${ap.goals.join(", ")}`);
  }

  return lines.join("\n");
}

function renderDeploymentSection(model: ThreatModel): string {
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
  lines.push("| ID | Name | Type | Technology | Trust Boundary |");
  lines.push("|----|------|------|------------|----------------|");
  for (const c of components) {
    lines.push(
      `| ${c.id} | ${c.name} | ${formatType(c.type)} | ${c.technology} | ${c.trustBoundary} |`,
    );
  }
  return lines.join("\n");
}

function renderTrustBoundariesSection(model: ThreatModel): string {
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

function renderSecurityControlsSection(sc: SecurityControlsResult): string {
  const lines: string[] = ["## Security Controls"];

  for (let i = 0; i < sc.controls.length; i++) {
    const ctrl = sc.controls[i]!;
    lines.push("");
    lines.push(`### SC-${i + 1}: ${ctrl.name}`);
    lines.push(`- **Type:** ${ctrl.type}`);
    lines.push(`- **Effectiveness:** ${capitalize(ctrl.effectiveness)}`);
    lines.push(`- **Scope:** ${ctrl.scope}`);
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

    // Mechanism
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

function renderSummarySection(model: ThreatModel): string {
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
    "| Severity | Count |",
    "|----------|-------|",
    `| Critical | ${s.attackPathsBySeverity.critical} |`,
    `| High | ${s.attackPathsBySeverity.high} |`,
    `| Medium | ${s.attackPathsBySeverity.medium} |`,
    `| Low | ${s.attackPathsBySeverity.low} |`,
  ];

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// JSON serializer
// ---------------------------------------------------------------------------

/**
 * Serialize a threat model to pretty-printed JSON for programmatic use.
 */
export function serializeThreatModelToJson(model: ThreatModel): string {
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
