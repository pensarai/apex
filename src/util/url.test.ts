import { describe, it, expect } from "vitest";
import {
  parseTargetUrl,
  getAutoPopulatedHosts,
  getAutoPopulatedPorts,
} from "./url";

describe("URL Parsing Utilities", () => {
  describe("parseTargetUrl", () => {
    it("should parse a complete HTTPS URL", () => {
      const result = parseTargetUrl("https://example.com");
      expect(result).toEqual({
        hostname: "example.com",
        port: undefined,
      });
    });

    it("should parse a URL with explicit port", () => {
      const result = parseTargetUrl("https://example.com:8080");
      expect(result).toEqual({
        hostname: "example.com",
        port: 8080,
      });
    });

    it("should parse HTTP URLs", () => {
      const result = parseTargetUrl("http://api.example.com:3000");
      expect(result).toEqual({
        hostname: "api.example.com",
        port: 3000,
      });
    });

    it("should handle URLs with paths", () => {
      const result = parseTargetUrl("https://example.com:9000/api/v1/test");
      expect(result).toEqual({
        hostname: "example.com",
        port: 9000,
      });
    });

    it("should assume HTTPS for URLs without protocol", () => {
      const result = parseTargetUrl("example.com");
      expect(result).toEqual({
        hostname: "example.com",
        port: undefined,
      });
    });

    it("should parse host:port without protocol", () => {
      const result = parseTargetUrl("example.com:8080");
      expect(result).toEqual({
        hostname: "example.com",
        port: 8080,
      });
    });

    it("should return null for empty input", () => {
      expect(parseTargetUrl("")).toBeNull();
      expect(parseTargetUrl("   ")).toBeNull();
    });

    it("should handle simple hostnames with permissive parsing", () => {
      // Even "not-a-url" becomes valid with https:// prefix
      const result = parseTargetUrl("not-a-url");
      expect(result).toEqual({
        hostname: "not-a-url",
        port: undefined,
      });
    });

    it("should handle localhost", () => {
      const result = parseTargetUrl("http://localhost:3000");
      expect(result).toEqual({
        hostname: "localhost",
        port: 3000,
      });
    });

    it("should handle IP addresses", () => {
      const result = parseTargetUrl("https://192.168.1.1:8443");
      expect(result).toEqual({
        hostname: "192.168.1.1",
        port: 8443,
      });
    });
  });

  describe("getAutoPopulatedHosts", () => {
    it("should add parsed hostname to empty list", () => {
      const result = getAutoPopulatedHosts("https://example.com");
      expect(result).toEqual(["example.com"]);
    });

    it("should add parsed hostname to existing hosts", () => {
      const result = getAutoPopulatedHosts("https://api.example.com", [
        "example.com",
      ]);
      expect(result).toEqual(["example.com", "api.example.com"]);
    });

    it("should not duplicate existing hosts", () => {
      const result = getAutoPopulatedHosts("https://example.com", [
        "example.com",
      ]);
      expect(result).toEqual(["example.com"]);
    });

    it("should add even simple hostnames (permissive parsing)", () => {
      // "invalid" becomes "https://invalid" which has hostname "invalid"
      const result = getAutoPopulatedHosts("invalid", ["example.com"]);
      expect(result).toEqual(["example.com", "invalid"]);
    });

    it("should handle multiple existing hosts", () => {
      const result = getAutoPopulatedHosts("https://new.example.com", [
        "example.com",
        "api.example.com",
      ]);
      expect(result).toEqual([
        "example.com",
        "api.example.com",
        "new.example.com",
      ]);
    });
  });

  describe("getAutoPopulatedPorts", () => {
    it("should add parsed port to empty list", () => {
      const result = getAutoPopulatedPorts("https://example.com:8080");
      expect(result).toEqual([8080]);
    });

    it("should add parsed port to existing ports", () => {
      const result = getAutoPopulatedPorts("https://example.com:9000", [
        443, 8080,
      ]);
      expect(result).toEqual([443, 8080, 9000]);
    });

    it("should not duplicate existing ports", () => {
      const result = getAutoPopulatedPorts("https://example.com:8080", [8080]);
      expect(result).toEqual([8080]);
    });

    it("should preserve existing ports for URL without port", () => {
      const result = getAutoPopulatedPorts("https://example.com", [443, 8080]);
      expect(result).toEqual([443, 8080]);
    });

    it("should return empty list for URL without port and no existing ports", () => {
      const result = getAutoPopulatedPorts("https://example.com");
      expect(result).toEqual([]);
    });

    it("should preserve existing ports when target has no explicit port", () => {
      const result = getAutoPopulatedPorts("invalid", [443]);
      expect(result).toEqual([443]); // "invalid" has no port, so no change
    });
  });
});
