import type { AIModel } from "../../ai";
import type { AIAuthConfig } from "../../ai/utils";
import type { Session } from "../../session";
import type {
  DocumentedAssetRecord,
  AttackSurfaceReport,
} from "../../agents/legacy/attackSurfaceAgent/schemas";

/**
 * Shared context passed to every tool factory.
 *
 * Each tool receives what it needs from here — session paths,
 * abort signal, etc. — so individual tool files never import
 * session or agent internals directly.
 */
export type ToolContext = {
  /** Session providing paths for findings, POCs, logs, scratchpad, etc. */
  session: Session.SessionInfo;

  /** The target URL / host — needed by browser tools for context */
  target?: string;

  /** Signal to cancel in-flight operations */
  abortSignal?: AbortSignal;

  /** AI model — needed by tools that delegate to sub-agents */
  model?: AIModel;

  /** Per-provider API key overrides — needed by tools that spawn sub-agents */
  authConfig?: AIAuthConfig;

  /** Optional persistence callbacks for external storage integration */
  persistence?: PersistenceCallbacks;
};

/**
 * Callbacks for persisting agent discoveries to external storage (e.g., database).
 * These are optional — if not provided, assets are only written to the local filesystem.
 */
export type PersistenceCallbacks = {
  /** Called when an asset is documented via the document_asset tool. */
  onAssetDocumented?: (asset: DocumentedAssetRecord) => Promise<void>;

  /** Called when the final attack surface report is created. */
  onReportCreated?: (report: AttackSurfaceReport) => Promise<void>;

  /** Called for generic progress updates during analysis. */
  onProgressUpdate?: (update: { type: string; data: unknown }) => Promise<void>;
};
