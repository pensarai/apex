import { beforeEach, describe, expect, it, vi } from "vitest";

const apiRequest = vi.hoisted(() => vi.fn());

vi.mock("./apiClient", () => ({ apiRequest }));

import { createDomain, listDomains } from "./domains";

describe("domains API", () => {
  beforeEach(() => {
    apiRequest.mockReset();
  });

  it("lists domains in the authenticated workspace", async () => {
    apiRequest.mockResolvedValue({ domains: [] });

    await listDomains();

    expect(apiRequest).toHaveBeenCalledWith("GET", "/domains");
  });

  it("creates or resolves a canonical workspace domain", async () => {
    apiRequest.mockResolvedValue({
      id: "domain-1",
      url: "https://example.com",
      verified: false,
    });

    await createDomain({ url: "example.com" });

    expect(apiRequest).toHaveBeenCalledWith("POST", "/domains", {
      url: "example.com",
    });
  });
});
