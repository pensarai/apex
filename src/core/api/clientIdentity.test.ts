import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../installation", () => ({ getCurrentVersion: () => "1.4.2" }));

import {
  CLIENT_HEADERS,
  clientIdentityHeaders,
  getCurrentCommand,
  setCurrentCommand,
} from "./clientIdentity";

beforeEach(() => {
  setCurrentCommand(undefined);
});

describe("clientIdentityHeaders", () => {
  it("names the client and its version on every request", () => {
    expect(clientIdentityHeaders()).toEqual({
      [CLIENT_HEADERS.client]: "cli",
      [CLIENT_HEADERS.version]: "1.4.2",
    });
  });

  it("includes the command once the router has set one", () => {
    setCurrentCommand("pentests");
    expect(clientIdentityHeaders()[CLIENT_HEADERS.command]).toBe("pentests");
  });

  it("omits the command header entirely when there is none", () => {
    expect(clientIdentityHeaders()).not.toHaveProperty(CLIENT_HEADERS.command);
  });
});

describe("setCurrentCommand", () => {
  it("normalizes case and surrounding whitespace", () => {
    setCurrentCommand("  Issues  ");
    expect(getCurrentCommand()).toBe("issues");
  });

  // Console drops anything that is not a short lowercase identifier, so sending
  // it would be noise. The router passes raw argv, which can be anything.
  it("drops a command Console would reject rather than sending it", () => {
    for (const raw of [
      "a".repeat(64),
      "--prompt",
      "issues list",
      "../traversal",
      "https://example.com",
      "",
    ]) {
      setCurrentCommand(raw);
      expect(getCurrentCommand()).toBeUndefined();
    }
  });

  it("clears a previously set command when given nothing", () => {
    setCurrentCommand("issues");
    setCurrentCommand(undefined);
    expect(getCurrentCommand()).toBeUndefined();
  });
});
