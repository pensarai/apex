import { afterEach, expect, it, vi } from "vitest";
import { providerFetch } from "./providerFetch";

vi.mock("node:tls", () => ({
  default: {
    getCACertificates: (type: string) =>
      type === "system"
        ? ["system-ca", "shared-ca"]
        : ["default-ca", "shared-ca"],
  },
}));

afterEach(() => vi.unstubAllGlobals());

it("adds system CAs to Bun provider requests and honors an explicit CA", async () => {
  vi.stubGlobal("Bun", {});
  const fetch = vi.fn().mockResolvedValue(new Response());
  vi.stubGlobal("fetch", fetch);
  const url = "https://provider.example";
  const signal = new AbortController().signal;

  await providerFetch(url, { signal });
  await providerFetch(url, { tls: { ca: "explicit-ca" } });

  expect(fetch).toHaveBeenNthCalledWith(1, url, {
    signal,
    tls: { ca: ["default-ca", "shared-ca", "system-ca"] },
  });
  expect(fetch).toHaveBeenNthCalledWith(2, url, {
    tls: { ca: "explicit-ca" },
  });
});
