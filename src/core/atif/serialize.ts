import { createHash } from "node:crypto";
import { posix } from "node:path";
import {
  stringifyCanonicalJson,
  toJsonValue,
} from "../ai/native-rollout-evidence";
import {
  AtifConversionError,
  convertNativeRolloutSourcesToAtif,
} from "./convert";
import type {
  AtifBundleFile,
  AtifDiagnostic,
  AtifExportBundleV1,
  AtifTrajectoryV1_8,
  ConvertNativeRolloutToAtifInput,
  TrajectoryBundleManifestV1,
} from "./schema";
import {
  APEX_ATIF_EXPORTER_VERSION,
  ATIF_REFERENCE_REVISION,
  ATIF_SCHEMA_VERSION,
  TRAJECTORY_BUNDLE_FILENAME,
  TRAJECTORY_BUNDLE_LIMITS,
  TRAJECTORY_BUNDLE_TYPE,
  TRAJECTORY_BUNDLE_VERSION,
  TrajectoryBundleManifestSchema,
} from "./schema";
import { collectAtifValidationDiagnostics } from "./validate";

function hashBytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function bundleFile(
  kind: AtifBundleFile["kind"],
  path: string,
  mediaType: string,
  bytes: Uint8Array,
): AtifBundleFile {
  return {
    kind,
    path,
    mediaType,
    bytes,
    sha256: hashBytes(bytes),
    sizeBytes: bytes.byteLength,
  };
}

function diagnostic(
  code: string,
  message: string,
  path?: string,
): AtifDiagnostic {
  return {
    code,
    severity: "error",
    message,
    ...(path ? { path } : {}),
  };
}

function isExternalPath(path: string): boolean {
  try {
    const url = new URL(path);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

function validateDocumentReferences(
  trajectory: AtifTrajectoryV1_8,
  path: string,
  documentPath: string,
  documentPaths: ReadonlySet<string>,
  assetPaths: ReadonlySet<string>,
  diagnostics: AtifDiagnostic[],
): void {
  if (
    trajectory.continued_trajectory_ref &&
    !documentPaths.has(
      posix.join(
        posix.dirname(documentPath),
        trajectory.continued_trajectory_ref,
      ),
    )
  ) {
    diagnostics.push(
      diagnostic(
        "unresolved-continuation-reference",
        "continued_trajectory_ref does not resolve to a bundle document",
        `${path}.continued_trajectory_ref`,
      ),
    );
  }

  for (const [stepIndex, step] of trajectory.steps.entries()) {
    const contentParts = [
      ...(Array.isArray(step.message) ? step.message : []),
      ...(step.observation?.results ?? []).flatMap((result) =>
        Array.isArray(result.content) ? result.content : [],
      ),
    ];
    for (const [partIndex, part] of contentParts.entries()) {
      if (
        part.type !== "text" &&
        !isExternalPath(part.source.path) &&
        !assetPaths.has(
          posix.join(posix.dirname(documentPath), part.source.path),
        )
      ) {
        diagnostics.push(
          diagnostic(
            "unresolved-asset-reference",
            "multimodal content path does not resolve to a bundle asset",
            `${path}.steps[${stepIndex}].content[${partIndex}]`,
          ),
        );
      }
    }
    for (const [resultIndex, result] of (
      step.observation?.results ?? []
    ).entries()) {
      for (const [referenceIndex, reference] of (
        result.subagent_trajectory_ref ?? []
      ).entries()) {
        if (
          reference.trajectory_path &&
          !isExternalPath(reference.trajectory_path) &&
          !documentPaths.has(
            posix.join(posix.dirname(documentPath), reference.trajectory_path),
          )
        ) {
          diagnostics.push(
            diagnostic(
              "unresolved-subagent-document",
              "subagent trajectory_path does not resolve to a bundle document",
              `${path}.steps[${stepIndex}].observation.results[${resultIndex}].subagent_trajectory_ref[${referenceIndex}]`,
            ),
          );
        }
      }
    }
  }

  for (const [index, child] of (
    trajectory.subagent_trajectories ?? []
  ).entries()) {
    validateDocumentReferences(
      child,
      `${path}.subagent_trajectories[${index}]`,
      documentPath,
      documentPaths,
      assetPaths,
      diagnostics,
    );
  }
}

function eligibilityDiagnostics(): AtifDiagnostic[] {
  return [
    {
      code: "sft-context-novelty-unavailable",
      severity: "warning",
      message:
        "per-attempt exports mark model-visible input as copied context, so this bundle does not assert SFT eligibility",
    },
    {
      code: "rl-training-contract-unavailable",
      severity: "warning",
      message:
        "the recorded boundary has no attributable reward, policy revision, or trainer mask contract, so this bundle does not assert RL eligibility",
    },
  ];
}

export function serializeAtifExportBundle(
  input: ConvertNativeRolloutToAtifInput,
): AtifExportBundleV1 {
  const draft = convertNativeRolloutSourcesToAtif(input);
  const files: AtifBundleFile[] = draft.files.map((file) =>
    bundleFile(file.kind, file.path, file.mediaType, file.bytes),
  );
  const diagnostics = [...draft.diagnostics];
  const documentEntries: Array<{
    path: string;
    trajectoryId: string;
    sha256: string;
    sizeBytes: number;
  }> = [];

  for (const trajectories of Object.values(draft.documents)) {
    for (const trajectory of trajectories) {
      const trajectoryId = trajectory.trajectory_id;
      if (!trajectoryId) {
        diagnostics.push(
          diagnostic(
            "missing-trajectory-id",
            "a serialized trajectory needs trajectory_id",
          ),
        );
        continue;
      }
      const path = draft.documentPaths.get(trajectoryId);
      if (!path) {
        diagnostics.push(
          diagnostic(
            "missing-document-path",
            "a serialized trajectory has no bundle path",
            trajectoryId,
          ),
        );
        continue;
      }
      const validation = collectAtifValidationDiagnostics(trajectory);
      diagnostics.push(
        ...validation.diagnostics.map((entry) => ({
          ...entry,
          path: entry.path ? `${path}:${entry.path}` : path,
        })),
      );
      const bytes = Buffer.from(
        stringifyCanonicalJson(toJsonValue(trajectory)),
      );
      const file = bundleFile("document", path, "application/json", bytes);
      files.push(file);
      documentEntries.push({
        path,
        trajectoryId,
        sha256: file.sha256,
        sizeBytes: file.sizeBytes,
      });
    }
  }

  const documentPaths = new Set(documentEntries.map((entry) => entry.path));
  const assetPaths = new Set(
    files.filter((file) => file.kind === "asset").map((file) => file.path),
  );
  for (const [sessionId, trajectories] of Object.entries(draft.documents)) {
    for (const [index, trajectory] of trajectories.entries()) {
      validateDocumentReferences(
        trajectory,
        `documents.${sessionId}[${index}]`,
        draft.documentPaths.get(trajectory.trajectory_id ?? "") ?? "",
        documentPaths,
        assetPaths,
        diagnostics,
      );
    }
  }

  if (
    !documentEntries.some(
      (entry) => entry.trajectoryId === draft.rootTrajectoryId,
    )
  ) {
    diagnostics.push(
      diagnostic(
        "unresolved-root-trajectory",
        "rootTrajectoryId does not resolve to a serialized document",
      ),
    );
  }

  const paths = new Set<string>();
  for (const file of files) {
    if (paths.has(file.path)) {
      diagnostics.push(
        diagnostic(
          "duplicate-bundle-path",
          "bundle paths must be unique",
          file.path,
        ),
      );
    }
    paths.add(file.path);
  }

  const validationFailed =
    diagnostics.some((entry) => entry.severity === "error") ||
    draft.independentValidation?.status === "failed";
  const transcriptPartial = diagnostics.length > 0;
  const samplingFields = [
    "promptTokenIds",
    "completionTokenIds",
    "logprobs",
    "tokenizer",
  ] as const;
  const samplingComplete = samplingFields.every(
    (field) => draft.nativeSampling[field].available === input.sources.length,
  );
  const samplingDocuments = new Set(
    Object.values(draft.documents)
      .flat()
      .filter((document) =>
        document.steps.some(
          (step) =>
            step.metrics?.prompt_token_ids !== undefined ||
            step.metrics?.completion_token_ids !== undefined ||
            step.metrics?.logprobs !== undefined,
        ),
      )
      .map((document) => document.trajectory_id),
  );
  const manifest: TrajectoryBundleManifestV1 = {
    type: TRAJECTORY_BUNDLE_TYPE,
    version: TRAJECTORY_BUNDLE_VERSION,
    rootTrajectoryId: draft.rootTrajectoryId,
    atif: {
      schemaVersion: ATIF_SCHEMA_VERSION,
      referenceRevision: ATIF_REFERENCE_REVISION,
    },
    exporter: draft.exporter,
    documents: documentEntries.sort((left, right) =>
      left.path.localeCompare(right.path),
    ),
    assets: files
      .filter((file) => file.kind === "asset")
      .map((file) => ({
        path: file.path,
        sha256: file.sha256,
        sizeBytes: file.sizeBytes,
        mediaType: file.mediaType,
        required: true,
      }))
      .sort((left, right) => left.path.localeCompare(right.path)),
    sources: files
      .filter((file) => file.kind === "source")
      .map((file) => ({
        id: file.path.slice("sources/".length, -".json".length),
        path: file.path,
        sha256: file.sha256,
        sizeBytes: file.sizeBytes,
      }))
      .sort((left, right) => left.path.localeCompare(right.path)),
    validation: {
      status: validationFailed ? "invalid" : "valid",
      validator: {
        name: "apex-atif-v1.8",
        version: APEX_ATIF_EXPORTER_VERSION,
      },
      independent: draft.independentValidation ?? {
        status: "not_run",
        detail:
          "no independent ATIF-v1.8 validator result was supplied to the exporter",
      },
      diagnostics,
    },
    completeness: {
      status: transcriptPartial ? "partial" : "complete",
      sftEligibility: "ineligible",
      rlEligibility: "ineligible",
      diagnostics: [...diagnostics, ...eligibilityDiagnostics()],
    },
    nativeSampling: {
      status: Object.values(draft.nativeSampling).some(
        (field) => field.available > 0,
      )
        ? samplingComplete
          ? "available"
          : "partial"
        : "unavailable",
      artifactPaths: documentEntries
        .filter((entry) => samplingDocuments.has(entry.trajectoryId))
        .map((entry) => entry.path),
      reason: samplingComplete
        ? null
        : "One or more native sampling fields were not exposed completely; see the per-field availability counts.",
      fields: draft.nativeSampling,
    },
  };
  const parsedManifest = TrajectoryBundleManifestSchema.parse(manifest);
  const manifestBytes = Buffer.from(
    stringifyCanonicalJson(toJsonValue(parsedManifest)),
  );
  files.push(
    bundleFile(
      "manifest",
      TRAJECTORY_BUNDLE_FILENAME,
      "application/json",
      manifestBytes,
    ),
  );
  if (
    files.length > TRAJECTORY_BUNDLE_LIMITS.files ||
    files.some((file) => file.sizeBytes > TRAJECTORY_BUNDLE_LIMITS.fileBytes) ||
    files.reduce((total, file) => total + file.sizeBytes, 0) >
      TRAJECTORY_BUNDLE_LIMITS.totalBytes
  ) {
    throw new AtifConversionError(
      "trajectory bundle exceeds portable export limits",
      [
        diagnostic(
          "bundle_size_limit",
          "Bundle limits include every document, asset, source, and the manifest.",
        ),
      ],
    );
  }
  files.sort((left, right) => left.path.localeCompare(right.path));

  return {
    manifest: parsedManifest,
    documents: draft.documents,
    files,
  };
}
