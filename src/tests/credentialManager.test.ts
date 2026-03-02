import { describe, it, expect, beforeEach } from "vitest";
import { CredentialManager } from "../core/credentials";
import type { StoredCredential } from "../core/credentials";
import type { AuthCredentials } from "../core/session";

describe("CredentialManager", () => {
  let cm: CredentialManager;

  beforeEach(() => {
    cm = new CredentialManager();
  });

  // =========================================================================
  // add / resolve
  // =========================================================================

  describe("add() and resolve()", () => {
    it("stores a username-password credential and resolves it", () => {
      const id = cm.add({
        username: "alice",
        password: "s3cret",
        role: "admin",
        loginUrl: "https://example.com/login",
      });

      expect(id).toMatch(/^cred_/);
      expect(cm.size).toBe(1);

      const stored = cm.resolve(id);
      expect(stored).toBeDefined();
      expect(stored!.username).toBe("alice");
      expect(stored!.password).toBe("s3cret");
      expect(stored!.role).toBe("admin");
      expect(stored!.type).toBe("username-password");
    });

    it("stores an api-key credential", () => {
      const id = cm.add({ apiKey: "sk-12345", label: "prod key" });

      const stored = cm.resolve(id);
      expect(stored!.type).toBe("api-key");
      expect(stored!.apiKey).toBe("sk-12345");
      expect(stored!.label).toBe("prod key");
    });

    it("stores a bearer-token credential", () => {
      const id = cm.add({
        tokens: { bearerToken: "jwt.abc.xyz" },
      });

      const stored = cm.resolve(id);
      expect(stored!.type).toBe("bearer-token");
      expect(stored!.tokens!.bearerToken).toBe("jwt.abc.xyz");
    });

    it("stores custom-headers credential", () => {
      const id = cm.add({
        tokens: { customHeaders: { "X-API-Key": "key123" } },
      });

      const stored = cm.resolve(id);
      expect(stored!.type).toBe("custom-headers");
    });

    it("stores cookies credential", () => {
      const id = cm.add({
        tokens: { cookies: "session=abc123" },
      });

      const stored = cm.resolve(id);
      expect(stored!.type).toBe("cookies");
    });

    it("infers composite type when multiple secret fields present", () => {
      const id = cm.add({
        username: "bob",
        password: "pass",
        apiKey: "key",
      });

      const stored = cm.resolve(id);
      expect(stored!.type).toBe("composite");
    });

    it("allows explicit type override", () => {
      const id = cm.add({
        username: "bob",
        password: "pass",
        type: "username-password",
      });

      const stored = cm.resolve(id);
      expect(stored!.type).toBe("username-password");
    });

    it("allows explicit id", () => {
      const id = cm.add({ id: "my-cred-1", username: "u", password: "p" });
      expect(id).toBe("my-cred-1");
      expect(cm.resolve("my-cred-1")).toBeDefined();
    });

    it("returns undefined for unknown IDs", () => {
      expect(cm.resolve("nonexistent")).toBeUndefined();
    });
  });

  // =========================================================================
  // addFromAuthCredentials
  // =========================================================================

  describe("addFromAuthCredentials()", () => {
    it("converts a legacy AuthCredentials to a stored credential", () => {
      const creds: AuthCredentials = {
        username: "admin",
        password: "admin123",
        loginUrl: "https://app.test/login",
        tokens: {
          bearerToken: "tok-abc",
          cookies: "sess=xyz",
        },
      };

      const id = cm.addFromAuthCredentials(creds, {
        label: "admin creds",
        role: "admin",
      });

      const stored = cm.resolve(id);
      expect(stored).toBeDefined();
      expect(stored!.username).toBe("admin");
      expect(stored!.password).toBe("admin123");
      expect(stored!.loginUrl).toBe("https://app.test/login");
      expect(stored!.tokens!.bearerToken).toBe("tok-abc");
      expect(stored!.tokens!.cookies).toBe("sess=xyz");
      expect(stored!.label).toBe("admin creds");
      expect(stored!.role).toBe("admin");
      expect(stored!.type).toBe("composite");
    });

    it("handles minimal AuthCredentials", () => {
      const id = cm.addFromAuthCredentials({ username: "u", password: "p" });
      expect(cm.resolve(id)!.type).toBe("username-password");
    });

    it("returns existing ID when duplicate credentials are added", () => {
      const creds: AuthCredentials = {
        username: "admin",
        password: "admin123",
        loginUrl: "https://app.test/login",
      };

      const id1 = cm.addFromAuthCredentials(creds);
      const id2 = cm.addFromAuthCredentials(creds);

      expect(id1).toBe(id2);
      expect(cm.size).toBe(1);
    });

    it("deduplicates credentials with matching tokens", () => {
      const creds: AuthCredentials = {
        username: "user",
        password: "pass",
        tokens: {
          bearerToken: "jwt.abc",
          cookies: "sess=xyz",
          customHeaders: { "X-Key": "val" },
        },
      };

      const id1 = cm.addFromAuthCredentials(creds);
      const id2 = cm.addFromAuthCredentials(creds);
      const id3 = cm.addFromAuthCredentials(creds);

      expect(id1).toBe(id2);
      expect(id2).toBe(id3);
      expect(cm.size).toBe(1);
    });

    it("stores separately when credentials differ", () => {
      const id1 = cm.addFromAuthCredentials({
        username: "admin",
        password: "pass1",
      });
      const id2 = cm.addFromAuthCredentials({
        username: "admin",
        password: "pass2",
      });

      expect(id1).not.toBe(id2);
      expect(cm.size).toBe(2);
    });
  });

  // =========================================================================
  // getReference / listReferences
  // =========================================================================

  describe("getReference() and listReferences()", () => {
    it("returns a sanitised reference without secrets", () => {
      const id = cm.add({
        username: "alice",
        password: "TopSecret!",
        apiKey: "sk-secret-key",
        role: "admin",
        label: "Main admin",
        loginUrl: "https://app.test/login",
        tokens: {
          bearerToken: "jwt.secret",
          customHeaders: { "X-API-Key": "hidden" },
        },
      });

      const ref = cm.getReference(id)!;

      expect(ref.id).toBe(id);
      expect(ref.username).toBe("alice");
      expect(ref.role).toBe("admin");
      expect(ref.label).toBe("Main admin");
      expect(ref.loginUrl).toBe("https://app.test/login");
      expect(ref.type).toBe("composite");
      expect(ref.customHeaderKeys).toEqual(["X-API-Key"]);

      // Secrets must NOT be in the reference
      expect((ref as unknown as StoredCredential).password).toBeUndefined();
      expect((ref as unknown as StoredCredential).apiKey).toBeUndefined();
      expect((ref as unknown as StoredCredential).tokens).toBeUndefined();
    });

    it("returns undefined for unknown ID", () => {
      expect(cm.getReference("nope")).toBeUndefined();
    });

    it("lists all references", () => {
      cm.add({ username: "a", password: "1", role: "admin" });
      cm.add({ username: "b", password: "2", role: "user" });
      cm.add({ apiKey: "k", label: "api" });

      const refs = cm.listReferences();
      expect(refs).toHaveLength(3);

      // Verify no secrets leaked
      for (const ref of refs) {
        expect((ref as unknown as StoredCredential).password).toBeUndefined();
        expect((ref as unknown as StoredCredential).apiKey).toBeUndefined();
      }
    });
  });

  // =========================================================================
  // remove / clear / size
  // =========================================================================

  describe("remove(), clear(), size", () => {
    it("removes a credential", () => {
      const id = cm.add({ username: "u", password: "p" });
      expect(cm.size).toBe(1);
      expect(cm.remove(id)).toBe(true);
      expect(cm.size).toBe(0);
      expect(cm.resolve(id)).toBeUndefined();
    });

    it("returns false for removing unknown ID", () => {
      expect(cm.remove("nope")).toBe(false);
    });

    it("clears all credentials", () => {
      cm.add({ username: "a", password: "1" });
      cm.add({ username: "b", password: "2" });
      expect(cm.size).toBe(2);

      cm.clear();
      expect(cm.size).toBe(0);
      expect(cm.listReferences()).toEqual([]);
    });
  });

  // =========================================================================
  // toAuthCredentials
  // =========================================================================

  describe("toAuthCredentials()", () => {
    it("converts back to legacy AuthCredentials format", () => {
      const id = cm.add({
        username: "alice",
        password: "pass",
        apiKey: "key",
        loginUrl: "https://app.test",
        additionalFields: { org: "acme" },
        tokens: { bearerToken: "tok", cookies: "c=v" },
      });

      const legacy = cm.toAuthCredentials(id);
      expect(legacy).toBeDefined();
      expect(legacy!.username).toBe("alice");
      expect(legacy!.password).toBe("pass");
      expect(legacy!.apiKey).toBe("key");
      expect(legacy!.loginUrl).toBe("https://app.test");
      expect(legacy!.additionalFields).toEqual({ org: "acme" });
      expect(legacy!.tokens!.bearerToken).toBe("tok");
      expect(legacy!.tokens!.cookies).toBe("c=v");
    });

    it("returns undefined for unknown ID", () => {
      expect(cm.toAuthCredentials("nope")).toBeUndefined();
    });
  });

  // =========================================================================
  // formatForPrompt
  // =========================================================================

  describe("formatForPrompt()", () => {
    it("returns empty string when no credentials stored", () => {
      expect(cm.formatForPrompt()).toBe("");
    });

    it("formats credentials safely for agent prompts", () => {
      cm.add({
        id: "cred-1",
        username: "admin",
        password: "TopSecret",
        role: "admin",
        label: "Admin account",
        loginUrl: "https://app.test/login",
      });
      cm.add({
        id: "cred-2",
        apiKey: "sk-hidden-key",
        label: "API key",
        role: "service",
      });

      const prompt = cm.formatForPrompt();

      // Should contain the IDs
      expect(prompt).toContain("cred-1");
      expect(prompt).toContain("cred-2");

      // Should contain non-secret metadata
      expect(prompt).toContain("admin");
      expect(prompt).toContain("Admin account");
      expect(prompt).toContain("API key");
      expect(prompt).toContain("service");
      expect(prompt).toContain("https://app.test/login");

      // Must NOT contain secrets
      expect(prompt).not.toContain("TopSecret");
      expect(prompt).not.toContain("sk-hidden-key");
    });

    it("includes custom header key names but not values", () => {
      cm.add({
        id: "cred-h",
        tokens: {
          customHeaders: { "X-API-Key": "secret-value-123" },
        },
      });

      const prompt = cm.formatForPrompt();
      expect(prompt).toContain("X-API-Key");
      expect(prompt).not.toContain("secret-value-123");
    });
  });

  // =========================================================================
  // context passthrough
  // =========================================================================

  describe("context passthrough", () => {
    it("surfaces context from metadata in references", () => {
      const id = cm.add({
        username: "admin",
        password: "secret",
        role: "admin",
        metadata: { context: "Use the admin login page at /admin/login" },
      });

      const ref = cm.getReference(id)!;
      expect(ref.context).toBe("Use the admin login page at /admin/login");
    });

    it("surfaces context from addFromAuthCredentials in references", () => {
      const id = cm.addFromAuthCredentials({
        username: "admin",
        password: "admin123",
        role: "admin",
        context: "Login via the main form, select 'Admin' from the role dropdown",
      });

      const ref = cm.getReference(id)!;
      expect(ref.context).toBe(
        "Login via the main form, select 'Admin' from the role dropdown",
      );
    });

    it("includes context in formatForPrompt output", () => {
      cm.addFromAuthCredentials({
        username: "tester",
        password: "pass",
        role: "qa",
        context: "Navigate to /qa-portal and use the SSO button",
      });

      const prompt = cm.formatForPrompt();
      expect(prompt).toContain(
        "Context: Navigate to /qa-portal and use the SSO button",
      );
    });

    it("omits context line when context is not set", () => {
      cm.add({
        id: "no-ctx",
        username: "user",
        password: "pass",
      });

      const prompt = cm.formatForPrompt();
      expect(prompt).not.toContain("Context:");
    });
  });

  // =========================================================================
  // Multiple credentials
  // =========================================================================

  describe("multiple credentials workflow", () => {
    it("supports storing and resolving multiple credentials", () => {
      const adminId = cm.add({
        username: "admin",
        password: "admin_pass",
        role: "admin",
        label: "Admin",
      });

      const userId = cm.add({
        username: "user",
        password: "user_pass",
        role: "user",
        label: "Regular user",
      });

      const apiId = cm.add({
        apiKey: "sk-test",
        role: "service",
        label: "Service account",
      });

      expect(cm.size).toBe(3);

      // Agent sees only references
      const refs = cm.listReferences();
      expect(refs).toHaveLength(3);
      const roles = refs.map((r) => r.role).sort();
      expect(roles).toEqual(["admin", "service", "user"]);

      // Tool execution resolves full secrets
      expect(cm.resolve(adminId)!.password).toBe("admin_pass");
      expect(cm.resolve(userId)!.password).toBe("user_pass");
      expect(cm.resolve(apiId)!.apiKey).toBe("sk-test");
    });
  });
});
