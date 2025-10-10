# Pensar Agent Architecture

This directory contains the autonomous penetration testing agent system with three specialized agents working together.

## Agent Overview

### 1. Pentest Agent (`pentestAgent/`)

**Purpose:** Deep, focused penetration testing of specific targets

**Capabilities:**

- Comprehensive black-box security testing
- Port scanning and service enumeration
- Web application vulnerability testing (SQLi, XSS, CSRF, etc.)
- Authentication and authorization testing
- SSL/TLS configuration review
- Detailed finding documentation with severity ratings
- Automated report generation

**Use When:** You have a specific target to thoroughly test

**Key Features:**

- Autonomous operation - no user interaction required
- Systematic methodology (recon → enumeration → testing → reporting)
- POC script generation for exploitable vulnerabilities
- Session-based findings management

### 2. Attack Surface Agent (`attackSurfaceAgent/`)

**Purpose:** Comprehensive reconnaissance and asset discovery

**Capabilities:**

- Domain and subdomain enumeration
- IP range identification and port scanning
- Web application discovery and mapping
- Cloud resource identification (S3, Azure, GCS)
- Technology stack identification
- High-value target identification for deep testing
- Structured results output for orchestration

**Use When:** You need to map an organization's complete attack surface

**Key Features:**

- Breadth-focused (find everything, don't test deeply)
- Structured JSON output with comprehensive schema
- Automated prioritization of targets
- Integration with pentest agents for delegation
- **Answer tool** returns structured results for orchestrator

**Answer Tool Schema:**
The attack surface agent provides structured results including:

- `summary`: Statistics and completion status
- `discoveredAssets`: Complete inventory (domains, IPs, web apps, cloud resources)
- `highValueTargets`: Prioritized targets with testing objectives
- `keyFindings`: Security observations from reconnaissance
- `recommendations`: Testing priorities and actions
- `metadata`: Session information and tooling used

### 3. Thorough Pentest Agent (`thoroughPentestAgent/`)

**Purpose:** Orchestrate comprehensive penetration testing engagements

**Capabilities:**

- Launch and coordinate attack surface analysis
- Review attack surface results
- Strategically spawn multiple pentest agents
- Monitor sub-agent execution
- Aggregate findings from all agents
- Generate comprehensive master reports
- Provide executive-level insights

**Use When:** You need a complete, comprehensive security assessment

**Key Features:**

- **Orchestration layer** - coordinates other agents
- Sequential workflow (attack surface → pentest agents → report)
- Parallel pentest agent execution
- Strategic target selection based on risk
- Comprehensive findings aggregation

## Agent Relationships

```
┌─────────────────────────────────────────────────────────────┐
│           Thorough Pentest Agent (Orchestrator)             │
│                                                               │
│  1. Launches attack surface agent                            │
│  2. Reviews structured results                               │
│  3. Spawns pentest agents for high-value targets            │
│  4. Aggregates all findings                                  │
│  5. Generates comprehensive report                           │
└─────────────────────────────────────────────────────────────┘
                    │                        │
                    │                        │
        ┌───────────▼──────────┐  ┌─────────▼────────────────┐
        │  Attack Surface      │  │  Pentest Agents          │
        │  Agent               │  │  (Multiple, Parallel)    │
        │                      │  │                          │
        │  • Maps assets       │  │  • Deep testing          │
        │  • Discovers targets │  │  • Exploitation          │
        │  • Returns JSON      │  │  • Finding docs          │
        └──────────────────────┘  └──────────────────────────┘
```

## Choosing the Right Agent

### Use **Pentest Agent** when:

- ✓ You have a specific target (URL, IP, domain)
- ✓ You want deep security testing
- ✓ You need detailed vulnerability findings
- ✓ Single target focus

**Example:**

```typescript
runPentestAgent({
  target: "app.example.com",
  objective: "Test web application for authentication and authorization flaws",
  model: "claude-4-sonnet",
});
```

### Use **Attack Surface Agent** when:

- ✓ You're starting with an organization name or domain
- ✓ You need to discover all assets
- ✓ You want to identify what to test
- ✓ You need structured output for automation
- ✓ Breadth over depth

**Example:**

```typescript
runAttackSurfaceAgent({
  target: "example.com",
  objective: "Map complete attack surface and identify high-value targets",
  model: "claude-4-sonnet",
});
```

The agent will return structured results via the **answer tool** that include:

- All discovered assets
- High-value targets with suggested objectives
- Prioritized testing recommendations

### Use **Thorough Pentest Agent** when:

- ✓ You want a complete, comprehensive assessment
- ✓ You need attack surface + deep testing
- ✓ You want automated orchestration
- ✓ You need executive-level reporting
- ✓ Full engagement workflow

**Example:**

```typescript
runThoroughPentestAgent({
  target: "example.com",
  objective: "Comprehensive security assessment of organization",
  model: "claude-4-sonnet",
});
```

The agent will:

1. Launch attack surface agent
2. Review results
3. Spawn 5-15 pentest agents for high-value targets
4. Aggregate all findings
5. Generate comprehensive report

## Tool Architecture

### Shared Tools (`tools.ts`)

All agents have access to:

- `execute_command` - Shell command execution
- `http_request` - HTTP/HTTPS requests
- `document_finding` - Finding documentation
- `analyze_scan` - Scan result analysis
- `scratchpad` - Note-taking
- `generate_report` - Report generation

### Attack Surface Specific Tools

- `answer` - Structured results output (JSON schema)

### Orchestrator Specific Tools

- `get_attack_surface` - Launch attack surface agent
- `run_pentest_agents` - Launch multiple pentest agents
- `read_attack_surface_results` - Read attack surface JSON
- `generate_final_report` - Master report generation

## Session Management

Each agent creates a session with:

- Unique session ID
- Dedicated directory structure
- Findings storage
- Scratchpad for notes
- Generated reports

**Session Structure:**

```
sessions/<target>-<timestamp>-<id>/
  ├── README.md                    # Session overview
  ├── session.json                 # Session metadata
  ├── findings/                    # Individual findings
  │   ├── finding-1.md
  │   └── finding-2.md
  ├── findings-summary.md          # Findings overview
  ├── scratchpad/                  # Agent notes
  │   └── notes.md
  ├── logs/                        # Execution logs
  ├── pentest-report.md           # Pentest agent report
  ├── attack-surface-results.json  # Attack surface results
  └── comprehensive-pentest-report.md # Orchestrator report
```

## Type System

### Attack Surface Types (`attackSurfaceAgent/types.ts`)

Complete TypeScript types for attack surface results:

- `AttackSurfaceAnalysisResults` - Full result structure
- `HighValueTarget` - Prioritized testing target
- `DiscoveredAssets` - Asset inventory
- Helper functions for orchestrator integration

**Usage Example:**

```typescript
import {
  AttackSurfaceAnalysisResults,
  extractPentestTargets,
  getHighPriorityTargets,
} from "./attackSurfaceAgent/types";

// Load results
const results: AttackSurfaceAnalysisResults = loadAttackSurfaceResults(path);

// Extract targets for pentesting
const targets = extractPentestTargets(results);

// Filter by priority
const critical = getHighPriorityTargets(results);
```

## Integration Examples

### Manual Workflow

```typescript
// Step 1: Attack surface analysis
const surfaceResult = runAttackSurfaceAgent({
  target: "example.com",
  objective: "Map complete attack surface",
});

// Step 2: Load results
const results = loadAttackSurfaceResults(
  surfaceResult.session.rootPath + "/attack-surface-results.json"
);

// Step 3: Select targets
const targets = getHighPriorityTargets(results);

// Step 4: Run pentest agents
for (const target of targets) {
  runPentestAgent({
    target: target.target,
    objective: target.objective,
  });
}
```

### Automated Workflow (Recommended)

```typescript
// Let the orchestrator handle everything
runThoroughPentestAgent({
  target: "example.com",
  objective: "Comprehensive security assessment",
});
// Done! The orchestrator coordinates all sub-agents automatically
```

## Best Practices

### For Attack Surface Agent:

1. Start with broad scope (organization domain)
2. Let the agent enumerate comprehensively
3. Review the highValueTargets in results
4. Use the suggested objectives for pentest agents

### For Pentest Agent:

1. Provide specific, focused targets
2. Write clear, actionable objectives
3. Let the agent run autonomously
4. Review the generated report

### For Thorough Pentest Agent:

1. Use for complete engagements
2. Trust the orchestrator's decisions
3. Review the comprehensive report
4. Share executive summary with stakeholders

## Configuration

Agents use the model specified in the function call:

- `claude-4-sonnet-20240229` - Recommended (balanced)
- `claude-4-opus-20240229` - Maximum capability (slower, more expensive)
- Other models as supported

## Extending the System

### Adding New Agent Types:

1. Create new directory under `agent/`
2. Implement `agent.ts` with `runAgent()` function
3. Create `prompts.ts` with `SYSTEM` prompt
4. Export from `index.ts`
5. Add tools if needed

### Adding New Tools:

1. Define in `tools.ts`
2. Add to `createPentestTools()` function
3. Document in agent prompts
4. Update this README

## Security Considerations

- Agents operate with shell access (sandboxed)
- Commands executed with user permissions
- Network access required for testing
- Store sessions securely (may contain sensitive findings)
- Review findings before sharing
- Comply with authorization requirements

## Troubleshooting

**Agent doesn't complete:**

- Check session logs in `sessions/<id>/logs/`
- Verify network connectivity
- Check model API availability

**Missing results:**

- Ensure agent completed successfully
- Check for `attack-surface-results.json` or `pentest-report.md`
- Review session directory structure

**Sub-agents not launching:**

- Verify orchestrator has model access
- Check for errors in tool execution
- Review orchestrator session logs

## Future Enhancements

- [ ] Parallel attack surface analysis of multiple domains
- [ ] Custom tool injection per agent type
- [ ] Real-time progress monitoring
- [ ] Result caching and reuse
- [ ] Interactive mode for user guidance
- [ ] Integration with vulnerability databases
- [ ] Automated retesting workflow
- [ ] Continuous monitoring mode
