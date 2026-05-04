/**
 * Trace integrity verification — APTS-AR-012 compliance.
 *
 * Implements the Chain Verification Algorithm specified in APTS-AR-012:
 * 1. Read all entries in order of sequence number
 * 2. For each entry, recompute hash: SHA256(content + previous_hash)
 * 3. Compare computed hash to stored integrityHash
 * 4. Verify sequence numbers are continuous (no gaps)
 * 5. If any mismatch or gap, log has been tampered with
 * 6. Break point indicates where modification occurred
 */

import { readFileSync } from "fs";
import {
  type HashChainEnvelope,
  GENESIS_HASH,
  computeChainHash,
} from "./trace";

// ---------------------------------------------------------------------------
// Verification result types
// ---------------------------------------------------------------------------

export interface TraceVerificationSuccess {
  valid: true;
  entriesVerified: number;
}

export interface TraceVerificationFailure {
  valid: false;
  entriesVerified: number;
  /** Sequence number where the chain breaks */
  breakPoint: number;
  reason:
    | "hash_mismatch"
    | "sequence_gap"
    | "sequence_regression"
    | "missing_fields"
    | "parse_error";
  details: string;
}

export type TraceVerificationResult =
  | TraceVerificationSuccess
  | TraceVerificationFailure;

// ---------------------------------------------------------------------------
// Verification implementation
// ---------------------------------------------------------------------------

/**
 * Verify the integrity of a trace.jsonl file by validating the hash chain.
 *
 * Reads the file, parses each line as a {@link HashChainEnvelope}, and
 * verifies:
 *  - Sequence numbers are continuous starting from 0
 *  - Each entry's integrityHash matches SHA-256(record_json + previous_hash)
 *
 * @param tracePath - Absolute path to the trace.jsonl file
 * @returns Verification result indicating success or the exact break point
 */
export function verifyTraceIntegrity(
  tracePath: string,
): TraceVerificationResult {
  const content = readFileSync(tracePath, "utf-8");
  return verifyTraceContent(content);
}

/**
 * Verify the integrity of trace content provided as a string.
 * Useful for testing and streaming verification scenarios.
 */
export function verifyTraceContent(content: string): TraceVerificationResult {
  const lines = content.split("\n").filter((line) => line.trim().length > 0);

  if (lines.length === 0) {
    return { valid: true, entriesVerified: 0 };
  }

  let previousHash = GENESIS_HASH;
  let expectedSeq = 0;

  for (let i = 0; i < lines.length; i++) {
    let envelope: HashChainEnvelope;

    try {
      envelope = JSON.parse(lines[i]) as HashChainEnvelope;
    } catch {
      return {
        valid: false,
        entriesVerified: i,
        breakPoint: expectedSeq,
        reason: "parse_error",
        details: `Line ${i} is not valid JSON`,
      };
    }

    if (
      envelope.seq === undefined ||
      envelope.integrityHash === undefined ||
      envelope.record === undefined
    ) {
      return {
        valid: false,
        entriesVerified: i,
        breakPoint: expectedSeq,
        reason: "missing_fields",
        details: `Line ${i} is missing required hash chain fields (seq, integrityHash, record)`,
      };
    }

    if (envelope.seq !== expectedSeq) {
      const reason =
        envelope.seq < expectedSeq ? "sequence_regression" : "sequence_gap";
      return {
        valid: false,
        entriesVerified: i,
        breakPoint: expectedSeq,
        reason,
        details: `Expected seq ${expectedSeq}, got ${envelope.seq} at line ${i}`,
      };
    }

    const serializedRecord = JSON.stringify(envelope.record);
    const computedHash = computeChainHash(serializedRecord, previousHash);

    if (computedHash !== envelope.integrityHash) {
      return {
        valid: false,
        entriesVerified: i,
        breakPoint: envelope.seq,
        reason: "hash_mismatch",
        details:
          `Hash mismatch at seq ${envelope.seq}: ` +
          `expected ${computedHash}, got ${envelope.integrityHash}`,
      };
    }

    previousHash = envelope.integrityHash;
    expectedSeq++;
  }

  return { valid: true, entriesVerified: lines.length };
}
