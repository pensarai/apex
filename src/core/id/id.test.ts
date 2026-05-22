import { describe, it, expect } from "vitest";
import {
  ascending,
  descending,
  newSessionId,
  newMessageId,
  newPartId,
  isSessionId,
  isMessageId,
  isPartId,
  schema,
} from "./id";

describe("id minting", () => {
  describe("format", () => {
    it("sessionId matches ses_<26> shape", () => {
      const id = newSessionId();
      expect(id).toMatch(/^ses_[0-9a-fA-F]{12}[0-9A-Za-z]{14}$/);
    });

    it("messageId matches msg_<26> shape", () => {
      const id = newMessageId();
      expect(id).toMatch(/^msg_[0-9a-fA-F]{12}[0-9A-Za-z]{14}$/);
    });

    it("partId matches prt_<26> shape", () => {
      const id = newPartId();
      expect(id).toMatch(/^prt_[0-9a-fA-F]{12}[0-9A-Za-z]{14}$/);
    });
  });

  describe("uniqueness", () => {
    it("100k session ids are all distinct", () => {
      const seen = new Set<string>();
      for (let i = 0; i < 100_000; i++) {
        seen.add(newSessionId());
      }
      expect(seen.size).toBe(100_000);
    });

    it("100k message ids are all distinct", () => {
      const seen = new Set<string>();
      for (let i = 0; i < 100_000; i++) {
        seen.add(newMessageId());
      }
      expect(seen.size).toBe(100_000);
    });

    it("100k part ids are all distinct", () => {
      const seen = new Set<string>();
      for (let i = 0; i < 100_000; i++) {
        seen.add(newPartId());
      }
      expect(seen.size).toBe(100_000);
    });

    it("session/message/part ids do not collide across kinds", () => {
      const seen = new Set<string>();
      for (let i = 0; i < 10_000; i++) {
        seen.add(newSessionId());
        seen.add(newMessageId());
        seen.add(newPartId());
      }
      expect(seen.size).toBe(30_000);
    });
  });

  describe("monotonicity within a tick (ascending order)", () => {
    it("ascending ids minted in the same millisecond sort by counter", () => {
      const a = ascending("session");
      const b = ascending("session");
      const c = ascending("session");
      expect(a < b).toBe(true);
      expect(b < c).toBe(true);
    });

    it("descending ids minted in the same millisecond sort newest-first", () => {
      const a = descending("session");
      const b = descending("session");
      const c = descending("session");
      expect(a > b).toBe(true);
      expect(b > c).toBe(true);
    });
  });

  describe("runtime guards", () => {
    it("isSessionId accepts a freshly minted session id", () => {
      expect(isSessionId(newSessionId())).toBe(true);
    });

    it("isSessionId rejects a message id", () => {
      expect(isSessionId(newMessageId())).toBe(false);
    });

    it("isSessionId rejects a part id", () => {
      expect(isSessionId(newPartId())).toBe(false);
    });

    it("isMessageId / isPartId are kind-discriminating", () => {
      const m = newMessageId();
      const p = newPartId();
      expect(isMessageId(m)).toBe(true);
      expect(isPartId(p)).toBe(true);
      expect(isMessageId(p)).toBe(false);
      expect(isPartId(m)).toBe(false);
    });

    it("rejects non-string values", () => {
      expect(isSessionId(undefined)).toBe(false);
      expect(isSessionId(null)).toBe(false);
      expect(isSessionId(123)).toBe(false);
      expect(isSessionId({})).toBe(false);
    });

    it("rejects strings with the right prefix but wrong body length", () => {
      expect(isSessionId("ses_")).toBe(false);
      expect(isSessionId("ses_short")).toBe(false);
      expect(isSessionId("ses_" + "a".repeat(25))).toBe(false);
      expect(isSessionId("ses_" + "a".repeat(27))).toBe(false);
    });

    it("rejects strings with the right body length but no underscore separator", () => {
      expect(isSessionId("sesa" + "a".repeat(26))).toBe(false);
    });
  });

  describe("zod schema", () => {
    it("schema('session') accepts a session id", () => {
      const s = schema("session");
      expect(s.safeParse(newSessionId()).success).toBe(true);
    });

    it("schema('session') rejects a message id", () => {
      const s = schema("session");
      expect(s.safeParse(newMessageId()).success).toBe(false);
    });

    it("schema requires the underscore separator (no 'sesfoo')", () => {
      const s = schema("session");
      expect(s.safeParse("sesfoo").success).toBe(false);
    });
  });
});
