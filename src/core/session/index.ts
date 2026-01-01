import z from "zod";
import path from "path";
import os from "os";
import { Identifier } from "../id/id";
import { Installation } from "../installation";
import { Storage } from "../storage";
import type { Message } from "../messages/types";
import { Messages } from "../messages";
import { RateLimiter } from "../services/rateLimiter";

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
        username: z.string(),
        password: z.string(),
        loginUrl: z.string().optional(),
        additionalFields: z.record(z.string(), z.string()).optional()
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

    const SessionConfigObject = z.object({
        offensiveHeaders: OffensiveHeadersConfigObject.optional(),
        sessionType: z.enum(['web-app']).optional(),
        mode: z.enum(['auto', 'driver']).optional(),
        outcomeGuidance: z.string().optional(),
        scopeConstraints: ScopeConstraintsObject.optional(),
        authCredentials: AuthCredentialsObject.optional(),
        authenticationInstructions: z.string().optional(),
        requestsPerSecond: z.number().optional(),
        /** Enable CVSS 4.0 scoring for findings (defaults to true if not specified) */
        enableCvssScoring: z.boolean().optional(),
        /** Model to use for CVSS scorer subagent (default: claude-4-5-haiku) */
        cvssModel: z.string().optional()
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
        _rateLimiter?: RateLimiter
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

}