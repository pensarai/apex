// Braintrust Type Definitions
//
// Comprehensive type definitions for Braintrust integration including configuration,
// span metadata for different operation types, and sensitive data patterns.
//
// The metadata interfaces are designed to capture relevant telemetry for three distinct
// operation types: agent execution, tool calls, and AI model interactions. Each type
// has specific fields that align with what Braintrust expects for observability.

// Configuration interface for Braintrust integration.
// Populated from environment variables in config.ts.
export interface BraintrustConfig {
    apiKey: string; // API key for Braintrust authentication (required)
    projectName?: string; // Project name in Braintrust (defaults to 'apex-pentest')
    enabled: boolean; // Whether Braintrust integration is enabled
    clientId?: string; // Optional client identifier for multi-client scenarios
    environment?: 'dev' | 'staging' | 'prod'; // Environment tag for separating dev/staging/prod data
}

// Metadata interface for agent execution spans in Braintrust.
// Captures high-level agent operation metrics including success rate,
// duration, and domain-specific metrics like findings and test coverage.
export interface AgentSpanMetadata {
    agent_type: 'thoroughPentest' | 'pentest' | 'attackSurface' | 'documentFinding' | 'benchmark' | 'swarm'; // Type of agent being executed
    session_id: string; // Unique session identifier to group related operations
    target?: string; // Target being tested (URL, IP, hostname, etc.)
    objective?: string; // Human-readable objective or goal of the agent
    model: string; // AI model used by the agent (e.g., 'gpt-4', 'claude-3')
    success?: boolean; // Whether the agent completed successfully
    duration_ms?: number; // Total execution duration in milliseconds (set by tracer)
    findings_count?: number; // Number of security findings discovered
    tests_performed?: number; // Number of individual tests performed
    coverage_percent?: number; // Percentage of attack surface covered (0-100)

    // Benchmark-specific metrics
    branches_count?: number; // Number of branches being tested (benchmark)
    branches_tested?: number; // Number of branches that completed testing (benchmark)
    successful_branches?: number; // Number of branches with successful tests (benchmark)
    failed_branches?: number; // Number of branches with failed tests (benchmark)

    // Swarm-specific metrics
    targets_count?: number; // Number of targets in swarm test (swarm)
    targets_tested?: number; // Number of targets that completed testing (swarm)
    successful_targets?: number; // Number of successful target tests (swarm)
    failed_targets?: number; // Number of failed target tests (swarm)

    // Pentest-specific metrics
    finding_severity?: string; // Severity of finding being documented (pentest)
    finding_title?: string; // Title of finding being documented (pentest)
    poc_created?: boolean; // Whether a POC was created (pentest)

    // Attack surface specific metrics
    assets_discovered?: number; // Number of assets discovered (attackSurface)
    high_value_targets?: number; // Number of high-value targets identified (attackSurface)
}

// Metadata interface for tool call spans in Braintrust.
// Captures individual tool execution details including inputs, outputs,
// and error information. Inputs/outputs should be truncated to avoid bloat.
export interface ToolSpanMetadata {
    tool_name: string; // Name of the security tool being executed (e.g., 'nmap', 'sqlmap')
    attack_type?: string; // Type of attack or scan (e.g., 'port-scan', 'sql-injection')
    endpoint?: string; // Target endpoint or URL being tested
    command?: string; // Command line or invocation string (for CLI tools)
    success?: boolean; // Whether the tool executed successfully (not finding vuln, but executed)
    error?: string; // Error message if tool execution failed
    duration_ms?: number; // Tool execution duration in milliseconds (set by tracer)
    truncated_input?: any; // Truncated representation of tool input (avoid PII/secrets)
    truncated_output?: any; // Truncated representation of tool output (avoid PII/secrets)

    // execute_command specific metrics
    timeout?: number; // Timeout for command execution in milliseconds
    stdout_length?: number; // Length of stdout output
    stderr_length?: number; // Length of stderr output
    error_type?: string; // Type of error that occurred (e.g., 'timeout', 'non-zero-exit')

    // http_request specific metrics
    url?: string; // URL being requested (sanitized)
    method?: string; // HTTP method (GET, POST, etc.)
    has_body?: boolean; // Whether request has a body
    status_code?: number; // HTTP response status code
    redirected?: boolean; // Whether request was redirected
    response_size?: number; // Size of response body in bytes

    // analyze_scan specific metrics
    scan_type?: string; // Type of scan being analyzed (nmap, nikto, etc.)
    target?: string; // Target being scanned (sanitized)
    results_length?: number; // Length of scan results
    open_ports_found?: number; // Number of open ports found in scan
    recommendations_count?: number; // Number of recommendations generated from analysis
}

// Metadata interface for AI model call spans in Braintrust.
// Captures model invocation details including token usage and latency.
// Used for tracking costs and performance of AI operations.
export interface AISpanMetadata {
    model: string; // Model identifier (e.g., 'gpt-4-turbo', 'claude-3-opus')
    provider: string; // AI provider name (e.g., 'openai', 'anthropic', 'azure')
    prompt_tokens?: number; // Number of tokens in the prompt
    completion_tokens?: number; // Number of tokens in the completion
    total_tokens?: number; // Total tokens used (prompt + completion)
    latency_ms?: number; // Model response latency in milliseconds (set by tracer)
    temperature?: number; // Sampling temperature used (0.0-2.0 typically)
    max_tokens?: number; // Maximum tokens allowed in completion
    has_tools?: boolean; // Whether tools were available in this step
    tool_count?: number; // Number of tools available or called
    text_content?: string; // Agent's reasoning/thinking text output
    tool_calls?: Array<{ // Tool calls made in this step
        tool_name: string;
        tool_call_id: string;
        args: any; // Sanitized arguments
    }>;
    tool_results?: Array<{ // Results from tool calls
        tool_name: string;
        tool_call_id: string;
        result: any; // Sanitized result
    }>;
}

// Sensitive data patterns for scrubbing before sending to Braintrust.
// Used to prevent leaking credentials, tokens, and other secrets in trace data.
// Apply these patterns when truncating inputs/outputs in ToolSpanMetadata.
export const SENSITIVE_PATTERNS = {
    headers: ['authorization', 'cookie', 'set-cookie', 'x-api-key', 'api-key'], // HTTP header names (case-insensitive)
    queryParams: ['password', 'token', 'key', 'secret', 'api_key', 'apikey'], // Query parameter names (case-insensitive)
    bodyFields: ['password', 'passwd', 'pwd', 'secret', 'token', 'api_key'], // Body field names (case-insensitive)
};