import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  StepTraceWriter,
  type HashChainEnvelope,
  GENESIS_HASH,
  computeChainHash,
} from "./trace";
import { verifyTraceIntegrity, verifyTraceContent } from "./traceIntegrity";

describe("APTS-AR-012: Tamper-Evident Logging with Hash Chains", () => {
  let tempDir: string;
  let tracePath: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "trace-integrity-"));
    tracePath = join(tempDir, "trace.jsonl");
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  describe("computeChainHash", () => {
    it("produces consistent SHA-256 output", () => {
      const hash = computeChainHash('{"type":"init"}', GENESIS_HASH);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);

      const hash2 = computeChainHash('{"type":"init"}', GENESIS_HASH);
      expect(hash2).toBe(hash);
    });

    it("produces different hashes for different content", () => {
      const h1 = computeChainHash('{"type":"init"}', GENESIS_HASH);
      const h2 = computeChainHash('{"type":"step"}', GENESIS_HASH);
      expect(h1).not.toBe(h2);
    });

    it("produces different hashes for different previous hashes", () => {
      const content = '{"type":"init"}';
      const h1 = computeChainHash(content, GENESIS_HASH);
      const h2 = computeChainHash(content, h1);
      expect(h1).not.toBe(h2);
    });
  });

  describe("StepTraceWriter hash chain envelope", () => {
    it("writes entries with seq, integrityHash, and record fields", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: "test-agent",
      });

      writer.writeInit({
        model: "claude-sonnet-4-20250514",
        activeTools: ["execute_command"],
        sessionId: "sess-1",
        systemPrompt: "You are a pentest agent.",
      });

      const content = readFileSync(tracePath, "utf-8");
      const lines = content.trim().split("\n");
      expect(lines).toHaveLength(1);

      const envelope: HashChainEnvelope = JSON.parse(lines[0]);
      expect(envelope.seq).toBe(0);
      expect(envelope.integrityHash).toMatch(/^[a-f0-9]{64}$/);
      expect(envelope.record.type).toBe("init");
    });

    it("maintains continuous sequence numbers across multiple writes", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: "test-agent",
      });

      writer.writeInit({
        model: "claude-sonnet-4-20250514",
        activeTools: ["execute_command"],
        sessionId: "sess-1",
        systemPrompt: "You are a pentest agent.",
      });

      writer.recordStep([], {
        inputTokens: 100,
        outputTokens: 50,
      });

      writer.recordStep([], {
        inputTokens: 200,
        outputTokens: 100,
      });

      const content = readFileSync(tracePath, "utf-8");
      const lines = content.trim().split("\n");
      expect(lines).toHaveLength(3);

      const envelopes = lines.map((l) => JSON.parse(l) as HashChainEnvelope);
      expect(envelopes[0].seq).toBe(0);
      expect(envelopes[1].seq).toBe(1);
      expect(envelopes[2].seq).toBe(2);
    });

    it("chains hashes correctly (each entry depends on previous)", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: "test-agent",
      });

      writer.writeInit({
        model: "claude-sonnet-4-20250514",
        activeTools: [],
        sessionId: "sess-1",
        systemPrompt: "Test prompt",
      });

      writer.recordStep([], { inputTokens: 10, outputTokens: 5 });

      const content = readFileSync(tracePath, "utf-8");
      const lines = content.trim().split("\n");
      const env0: HashChainEnvelope = JSON.parse(lines[0]);
      const env1: HashChainEnvelope = JSON.parse(lines[1]);

      const expectedHash0 = computeChainHash(
        JSON.stringify(env0.record),
        GENESIS_HASH,
      );
      expect(env0.integrityHash).toBe(expectedHash0);

      const expectedHash1 = computeChainHash(
        JSON.stringify(env1.record),
        env0.integrityHash,
      );
      expect(env1.integrityHash).toBe(expectedHash1);
    });
  });

  describe("verifyTraceIntegrity", () => {
    it("verifies a valid trace file", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: "test-agent",
      });

      writer.writeInit({
        model: "claude-sonnet-4-20250514",
        activeTools: ["execute_command", "http_request"],
        sessionId: "sess-1",
        systemPrompt: "You are a security researcher.",
      });

      writer.recordStep([], { inputTokens: 500, outputTokens: 200 });
      writer.recordStep([], { inputTokens: 600, outputTokens: 300 });

      const result = verifyTraceIntegrity(tracePath);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.entriesVerified).toBe(3);
      }
    });

    it("detects content modification (hash mismatch)", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: "test-agent",
      });

      writer.writeInit({
        model: "test-model",
        activeTools: [],
        sessionId: "sess-1",
        systemPrompt: "Test",
      });

      writer.recordStep([], { inputTokens: 100, outputTokens: 50 });
      writer.recordStep([], { inputTokens: 200, outputTokens: 100 });

      // Tamper with the second entry's record content
      const content = readFileSync(tracePath, "utf-8");
      const lines = content.trim().split("\n");
      const env1: HashChainEnvelope = JSON.parse(lines[1]);
      env1.record = { ...env1.record, type: "step" } as never;
      (env1.record as { stepIndex?: number }).stepIndex = 999;
      lines[1] = JSON.stringify(env1);
      writeFileSync(tracePath, lines.join("\n") + "\n");

      const result = verifyTraceIntegrity(tracePath);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe("hash_mismatch");
        expect(result.breakPoint).toBe(1);
      }
    });

    it("detects entry deletion (sequence gap)", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: "test-agent",
      });

      writer.writeInit({
        model: "test-model",
        activeTools: [],
        sessionId: "sess-1",
        systemPrompt: "Test",
      });

      writer.recordStep([], { inputTokens: 100, outputTokens: 50 });
      writer.recordStep([], { inputTokens: 200, outputTokens: 100 });
      writer.recordStep([], { inputTokens: 300, outputTokens: 150 });

      // Delete the second entry (seq 1)
      const content = readFileSync(tracePath, "utf-8");
      const lines = content.trim().split("\n");
      const tampered = [lines[0], lines[2], lines[3]].join("\n") + "\n";
      writeFileSync(tracePath, tampered);

      const result = verifyTraceIntegrity(tracePath);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe("sequence_gap");
        expect(result.breakPoint).toBe(1);
      }
    });

    it("detects entry insertion (sequence regression)", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: "test-agent",
      });

      writer.writeInit({
        model: "test-model",
        activeTools: [],
        sessionId: "sess-1",
        systemPrompt: "Test",
      });

      writer.recordStep([], { inputTokens: 100, outputTokens: 50 });

      // Insert a duplicate of entry 0 between entries 0 and 1
      const content = readFileSync(tracePath, "utf-8");
      const lines = content.trim().split("\n");
      const tampered = [lines[0], lines[0], lines[1]].join("\n") + "\n";
      writeFileSync(tracePath, tampered);

      const result = verifyTraceIntegrity(tracePath);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe("sequence_regression");
      }
    });

    it("returns valid for empty trace file", () => {
      writeFileSync(tracePath, "");
      const result = verifyTraceIntegrity(tracePath);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.entriesVerified).toBe(0);
      }
    });

    it("detects malformed JSON lines", () => {
      writeFileSync(tracePath, "not json at all\n");
      const result = verifyTraceIntegrity(tracePath);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe("parse_error");
      }
    });

    it("detects missing hash chain fields", () => {
      writeFileSync(
        tracePath,
        JSON.stringify({ type: "init", timestamp: "2024-01-01" }) + "\n",
      );
      const result = verifyTraceIntegrity(tracePath);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.reason).toBe("missing_fields");
      }
    });
  });

  describe("verifyTraceContent", () => {
    it("works with string content directly", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: null,
      });

      writer.writeInit({
        model: "test-model",
        activeTools: [],
        sessionId: "sess-1",
        systemPrompt: "Test",
      });

      const content = readFileSync(tracePath, "utf-8");
      const result = verifyTraceContent(content);
      expect(result.valid).toBe(true);
    });
  });

  describe("checkpoint and task records in chain", () => {
    it("includes checkpoint records in the hash chain", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: "test-agent",
      });

      writer.writeInit({
        model: "test-model",
        activeTools: [],
        sessionId: "sess-1",
        systemPrompt: "Test",
      });

      writer.appendCheckpoint({
        targetState: {
          discoveredSurface: ["https://example.com"],
          credentialsObtained: [],
          confirmedVulnerabilities: [],
        },
        actionsAttempted: [],
        nextSteps: [],
        blockers: [],
        assessment: "Initial checkpoint",
      });

      writer.recordStep([], { inputTokens: 100, outputTokens: 50 });

      const result = verifyTraceIntegrity(tracePath);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.entriesVerified).toBe(3);
      }
    });

    it("includes task records in the hash chain", () => {
      const writer = new StepTraceWriter({
        tracePath,
        agentId: "test-agent",
      });

      writer.writeInit({
        model: "test-model",
        activeTools: [],
        sessionId: "sess-1",
        systemPrompt: "Test",
      });

      writer.appendTaskRecord({
        action: "created",
        taskId: 1,
        data: {
          subject: "Test SQL injection",
          status: "pending",
          objective: "Find SQLi in login form",
          technique: "error-based injection",
        },
      });

      const result = verifyTraceIntegrity(tracePath);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.entriesVerified).toBe(2);
      }
    });
  });
});
