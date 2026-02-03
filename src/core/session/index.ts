import z from "zod";
import path from "path";
import os from "os";
import { existsSync, readFileSync, writeFileSync } from "fs";
import { Identifier } from "../id/id";
import { Installation } from "../installation";
import { Storage } from "../storage";
import type { Message } from "../messages/types";
import { Messages } from "../messages";
import { RateLimiter } from "../services/rateLimiter";
import { ToolsetStateSchema, type ToolsetState, toggleTool as toolsetToggle } from "../toolset";

export namespace Session {

    /**
     * Default outcome guidance (safe, non-destructive)
     */
    export const DEFAULT_OUTCOME_GUIDANCE =
    "Prove the exploit can be run but do not exfiltrate data or cause any harm to the system. " +
    "Create proof-of-concept exploits that demonstrate the vulnerability exists without causing damage.";

    /**
     * Benchmark outcome guidance (extract flags)
     */
    export const BENCHMARK_OUTCOME_GUIDANCE =
    "Exfiltrate data to extract the flag value. " +
    "Create proof-of-concept exploits that successfully extract the flag from the target system.";

    /**
     * Default headers for pensar-apex
     */
    export const DEFAULT_OFFENSIVE_HEADERS: Record<string, string> = {
        'User-Agent': 'pensar-apex',
    };


    const AuthCredentialsObject = z.object({
        // Username/password auth
        username: z.string().optional(),
        password: z.string().optional(),
        loginUrl: z.string().optional(),
        additionalFields: z.record(z.string(), z.string()).optional(),
        // API key auth
        apiKey: z.string().optional(),
        // Pre-existing tokens for verification
        tokens: z.object({
            bearerToken: z.string().optional(),
            cookies: z.string().optional(),
            sessionToken: z.string().optional(),
            customHeaders: z.record(z.string(), z.string()).optional(),
        }).optional(),
    });

    export type AuthCredentials = z.infer<typeof AuthCredentialsObject>;

    const ScopeConstraintsObject = z.object({
        allowedHosts: z.string().array().optional(),
        allowedPorts: z.number().array().optional(),
        strictScope: z.boolean().optional()
    });

    export type ScopeConstraints = z.infer<typeof ScopeConstraintsObject>;

    const OffensiveHeadersConfigObject = z.object({
        mode: z.enum(["none", "default", "custom"]),
        headers: z.record(z.string(), z.string()).optional()
    });

    export type OffensiveHeadersConfig = z.infer<typeof OffensiveHeadersConfigObject>;

    const OperatorSettingsObject = z.object({
        initialMode: z.enum(["plan", "manual", "auto"]).default("manual"),
        autoApproveTier: z.number().min(1).max(5).default(2),
        enableSuggestions: z.boolean().default(true),
    });

    export type OperatorSettings = z.infer<typeof OperatorSettingsObject>;

    const SessionConfigObject = z.object({
        offensiveHeaders: OffensiveHeadersConfigObject.optional(),
        sessionType: z.enum(['web-app']).optional(),
        mode: z.enum(['auto', 'driver', 'operator']).optional(),
        outcomeGuidance: z.string().optional(),
        scopeConstraints: ScopeConstraintsObject.optional(),
        authCredentials: AuthCredentialsObject.optional(),
        authenticationInstructions: z.string().optional(),
        requestsPerSecond: z.number().optional(),
        operatorSettings: OperatorSettingsObject.optional(),
        /** Enable CVSS 4.0 scoring for findings (defaults to true if not specified) */
        enableCvssScoring: z.boolean().optional(),
        /** Model to use for CVSS scorer subagent (default: claude-4-5-haiku) */
        cvssModel: z.string().optional(),
        /** Toolset state for controlling which tools are available */
        toolsetState: ToolsetStateSchema.optional()
    });

    export type SessionConfig = z.infer<typeof SessionConfigObject>;

    // ============================================================================
    // ExecutionSession - Legacy-compatible session interface for agent consumption
    // ============================================================================

    /**
     * Legacy-compatible session interface that provides directory paths
     * for agent artifact storage (findings, POCs, logs, etc.)
     *
     * This replaces the old core/agent/sessions module with safe Storage writes.
     */
    export interface ExecutionSession {
        /** Unique session identifier (format: {prefix}-ses_{timestamp}_{random}) */
        id: string;
        /** Root path for all session artifacts (~/.pensar/executions/{id}) */
        rootPath: string;
        /** Path for security findings (~/.pensar/executions/{id}/findings) */
        findingsPath: string;
        /** Path for agent scratchpad notes (~/.pensar/executions/{id}/scratchpad) */
        scratchpadPath: string;
        /** Path for execution logs (~/.pensar/executions/{id}/logs) */
        logsPath: string;
        /** Path for proof-of-concept scripts (~/.pensar/executions/{id}/pocs) */
        pocsPath: string;
        /** Target URL or system being tested */
        target: string;
        /** Testing objective description */
        objective: string;
        /** ISO timestamp when session was created */
        startTime: string;
        /** Session configuration */
        config?: SessionConfig;
    }

    /**
     * Input for creating an execution session
     */
    export interface CreateExecutionInput {
        session: SessionInfo;
        /** Target URL or system to test */
        // target: string;
        // /** Testing objective description */
        // objective?: string;
        // /** Optional prefix for session ID (e.g., "benchmark-XBEN-001-24") */
        // prefix?: string;
        // /** Session configuration */
        // config?: SessionConfig;
    }

    /**
     * Get the base Pensar directory path
     */
    export function getPensarDir(): string {
        return path.join(os.homedir(), ".pensar");
    }

    /**
     * Get the executions directory path
     */
    export function getExecutionsDir(): string {
        return path.join(getPensarDir(), "executions");
    }

    /**
     * Get the root path for a session's execution directory
     */
    export function getExecutionRoot(id: string): string {
        console.log("GET EXECUTION ROOT", id);
        return path.join(getExecutionsDir(), id);
    }

    /**
     * Create a new execution session with directory structure for agent artifacts.
     * Uses Storage namespace for safe writes with locking.
     *
     * Directory structure created:
     * ~/.pensar/executions/{id}/
     * ├── session.json      # Session metadata
     * ├── README.md         # Session documentation
     * ├── findings/         # Security findings
     * ├── scratchpad/       # Agent notes
     * ├── logs/             # Execution logs
     * └── pocs/             # Proof-of-concept scripts
     */
    export async function createExecution(input: CreateExecutionInput): Promise<void> {
        const { session } = input;

        // Create directory structure with locking
        await Storage.createDir(["executions", session.id]);
        await Storage.createDir(["executions", session.id, "findings"]);
        await Storage.createDir(["executions", session.id, "scratchpad"]);
        await Storage.createDir(["executions", session.id, "logs"]);
        await Storage.createDir(["executions", session.id, "pocs"]);

        const startTime = new Date().toISOString();

        // Write README.md
        const readme = generateSessionReadme(session);
        await Storage.writeRaw(["executions", session.id, "README.md"], readme);

        console.info("created execution session", session.id);
    }

    /**
     * Generate README.md content for a session
     */
    function generateSessionReadme(session: SessionInfo): string {
        return `# Penetration Test Session

**Session ID:** ${session.id}
**Target:** ${session.targets}
**Objective:** ${session.config?.outcomeGuidance}
**Started:** ${session.time.created}

## Directory Structure

- \`findings/\` - Security findings and vulnerabilities
- \`scratchpad/\` - Notes and temporary data during testing
- \`logs/\` - Execution logs and command outputs
- \`pocs/\` - Proof-of-concept exploit scripts
- \`session.json\` - Session metadata

## Findings

Security findings will be documented in the \`findings/\` directory as individual files.

## Status

Testing in progress...
`;
    }

    /**
     * Get an execution session by ID
     */
    export async function getExecution(sessionId: string): Promise<ExecutionSession | null> {
        try {
            const metadata = await Storage.read<ExecutionSession & { version: string; time: { created: number; updated: number } }>(
                ["executions", sessionId, "session"]
            );
            return metadata;
        } catch (e) {
            if (e instanceof Storage.NotFoundError) {
                return null;
            }
            throw e;
        }
    }

    /**
     * Resolve offensive headers based on session config
     */
    export function getOffensiveHeaders(session: SessionInfo): Record<string, string> | undefined {
        const config = session.config?.offensiveHeaders;

        if (!config || config.mode === 'none') {
            return undefined;
        }

        if (config.mode === 'default') {
            return DEFAULT_OFFENSIVE_HEADERS;
        }

        if (config.mode === 'custom' && config.headers) {
            return config.headers;
        }

        return undefined;
    }

    // ============================================================================
    // SessionInfo - Original session metadata interface
    // ============================================================================

    export const SessionInfoObject = z.object({
        id: Identifier.schema("session"),
        name: z.string(),
        version: z.string(),
        targets: z.array(z.string()),
        config: SessionConfigObject.optional(),
        time: z.object({
            created: z.number(),
            updated: z.number(),
        }),
        rootPath: z.string(),
        logsPath: z.string(),
        findingsPath: z.string(),
        scratchpadPath: z.string(),
        pocsPath: z.string()
    }).meta({
        ref: "Session"
    });

    export type SessionInfo = z.output<typeof SessionInfoObject> & {
        _rateLimiter?: RateLimiter;
        tokensIn?: number;
        tokensOut?: number;
    };

    interface CreateInputProps {
        id?: string;
        targets: string[];
        name: string;
        prefix?: string;
        config?: SessionConfig;
        // offensiveHeaders?: OffensiveHeadersConfig;
        // outcomeGuidance?: string;
    }

    export async function create(input: CreateInputProps) {
        const id = `${input.prefix ? input.prefix : ""}` + Identifier.descending('session', input.id);
        
        const rootPath = getExecutionRoot(id);
        const findingsPath = path.join(rootPath, "findings");
        const scratchpadPath = path.join(rootPath, "scratchpad");
        const logsPath = path.join(rootPath, "logs");
        const pocsPath = path.join(rootPath, "pocs");

        const rateLimiter = new RateLimiter({ requestsPerSecond: input.config?.requestsPerSecond});

        const result: SessionInfo = {
            id: id,
            version: await Installation.getVersion(),
            targets: input.targets,
            name: input.name,
            time: {
                created: Date.now(),
                updated: Date.now()
            },
            config: {
                mode: input.config?.mode || "auto",
                offensiveHeaders: input.config?.offensiveHeaders || {
                    mode: "default",
                    headers: {
                        "User-Agent": "pensar-apex"
                    }
                },
                outcomeGuidance: input.config?.outcomeGuidance || DEFAULT_OUTCOME_GUIDANCE,
                scopeConstraints: input.config?.scopeConstraints,
                enableCvssScoring: input.config?.enableCvssScoring,
                cvssModel: input.config?.cvssModel
            },
            _rateLimiter: rateLimiter,
            rootPath,
            logsPath,
            pocsPath,
            scratchpadPath,
            findingsPath
        };

        

        console.info("created session", result);

        // Exclude _rateLimiter from serialization (it's a class instance with methods)
        const { _rateLimiter, ...sessionData } = result;
        await Storage.write(["session", result.id], sessionData);
        // await Storage.createDir(["executions", result.id]);
        await createExecution({ session: result });
        return result;
    }

    export const get = async (id: string) => {
        const read = await Storage.read<SessionInfo>(["session", id]);

        // Reconstruct RateLimiter instance (it gets serialized as plain object)
        // This ensures the session has a proper RateLimiter with methods
        if (read.config?.requestsPerSecond) {
            read._rateLimiter = new RateLimiter({
                requestsPerSecond: read.config.requestsPerSecond
            });
        } else {
            // Remove any stale serialized _rateLimiter data (plain object without methods)
            delete read._rateLimiter;
        }

        return read;
    }

    export const executionPath = (id: string) => Storage.locate(["executions", id], "");


    export async function update(id: string, editor: (session: SessionInfo) => void) {
        const result = await Storage.update<SessionInfo>(["session", id], (draft) => {
            editor(draft);
            draft.time.updated = Date.now()
        });
        console.info("updated session", result);
        return result;
    }

    const MessagesInput = z.object({
        sessionId: Identifier.schema("session"),
        limit: z.number().optional()
    });

    export const messages = async (input: z.output<typeof MessagesInput>) => {
        const result = [] as Message[];
        for await (const msg of Messages.stream(input)) {
            if(input.limit && result.length >= input.limit) break;
            result.push(msg);
        }
        result.reverse();
        return result;
    }

    export async function* list() {
        for (const item of await Storage.list(["session"])) {
            yield Storage.read<SessionInfo>(item);
        }
    }


    const RemoveInput = z.object({
        sessionId: Identifier.schema("session")
    });

    export const remove = async (input: z.output<typeof RemoveInput>) =>{
        try {
            const session = await get(input.sessionId);
            for (const msg of await Storage.list(["message", input.sessionId])) {
                await Storage.remove(msg);
            }
            await Storage.remove(["session", input.sessionId]);
        } catch(e) {
            console.error(e);
        }
    }

    export const updateMessage = async (msg: Message) => {
        await Storage.write(["message", msg.sessionId, msg.id], msg);
        return msg
    }

    const RemoveMsgInput = z.object({
        sessionId: Identifier.schema("session"),
        messageId: Identifier.schema("message")
    });

    export const removeMessage = async (input: z.output<typeof RemoveMsgInput>) => {
        await Storage.remove(["message", input.sessionId, input.messageId]);
        return input.messageId;
    }

    // ============================================================================
    // Operator Session State - For resume functionality
    // ============================================================================

    /**
     * Persisted operator dashboard state for session resumption
     */
    export interface OperatorSessionState {
        /** Operator mode: plan, manual, auto */
        mode: string;
        /** Auto-approve tier level */
        autoApproveTier: number;
        /** Current stage: setup, recon, foothold, etc. */
        currentStage: string;
        /** Chat messages history */
        messages: any[];
        /** Discovered attack surface endpoints */
        attackSurface: any[];
        /** Found credentials */
        credentials: any[];
        /** Verified vulnerabilities */
        verifiedVulns: any[];
        /** Target state (host, phase, objective) */
        targetState: any;
        /** Tracked hypotheses */
        hypotheses: any[];
        /** Collected evidence */
        evidence: any[];
        /** Action approval history */
        actionHistory: any[];
        /** When the session was paused */
        pausedAt: string;
        /** Last run ID for log correlation */
        lastRunId: string;
    }

    /**
     * Save operator dashboard state for later resumption
     */
    export async function saveOperatorState(
        sessionId: string,
        state: OperatorSessionState
    ): Promise<void> {
        const session = await get(sessionId);
        const statePath = path.join(session.rootPath, "operator-state.json");
        writeFileSync(statePath, JSON.stringify(state, null, 2));
        console.info("saved operator state for session", sessionId);
    }

    /**
     * Load operator dashboard state for session resumption
     */
    export async function loadOperatorState(
        sessionId: string
    ): Promise<OperatorSessionState | null> {
        try {
            const session = await get(sessionId);
            const statePath = path.join(session.rootPath, "operator-state.json");
            if (!existsSync(statePath)) return null;
            const data = readFileSync(statePath, "utf-8");
            return JSON.parse(data) as OperatorSessionState;
        } catch (error) {
            console.error("Error loading operator state:", error);
            return null;
        }
    }

    /**
     * Check if a session has saved operator state
     */
    export function hasOperatorState(session: SessionInfo): boolean {
        const statePath = path.join(session.rootPath, "operator-state.json");
        return existsSync(statePath);
    }

    // ============================================================================
    // Runtime Operator Settings Update
    // ============================================================================

    /**
     * Update operator settings for a running session
     * This persists the changes to the session config
     */
    export async function updateOperatorSettings(
        sessionId: string,
        settings: Partial<OperatorSettings>
    ): Promise<SessionInfo> {
        return await update(sessionId, (session) => {
            if (!session.config) {
                session.config = {};
            }
            if (!session.config.operatorSettings) {
                session.config.operatorSettings = {
                    initialMode: "manual",
                    autoApproveTier: 2,
                    enableSuggestions: true,
                };
            }

            // Update only the provided settings
            if (settings.initialMode !== undefined) {
                session.config.operatorSettings.initialMode = settings.initialMode;
            }
            if (settings.autoApproveTier !== undefined) {
                session.config.operatorSettings.autoApproveTier = settings.autoApproveTier;
            }
            if (settings.enableSuggestions !== undefined) {
                session.config.operatorSettings.enableSuggestions = settings.enableSuggestions;
            }
        });
    }

    // ============================================================================
    // Toolset State Management
    // ============================================================================

    /**
     * Update the toolset state for a session
     */
    export async function updateToolsetState(
        sessionId: string,
        toolsetState: ToolsetState
    ): Promise<SessionInfo> {
        return await update(sessionId, (session) => {
            if (!session.config) {
                session.config = {};
            }
            session.config.toolsetState = toolsetState;
        });
    }

    /**
     * Toggle a specific tool's enabled state
     */
    export async function toggleTool(
        sessionId: string,
        toolId: string,
        enabled: boolean
    ): Promise<SessionInfo> {
        return await update(sessionId, (session) => {
            if (!session.config) {
                session.config = {};
            }
            if (!session.config.toolsetState) {
                // Initialize with all tools enabled if no state exists
                const { createToolsetState } = require("../toolset");
                session.config.toolsetState = createToolsetState("web-pentest");
            }
            session.config.toolsetState = toolsetToggle(
                session.config.toolsetState!,
                toolId,
                enabled
            );
        });
    }

}