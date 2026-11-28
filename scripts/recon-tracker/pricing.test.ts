import { expect, it } from "vitest";
import { findPricing } from "./pricing";

it("prices native aliases without changing model routing or guessing ambiguous providers", () => {
  const opus = {
    id: "anthropic/claude-opus-4.6",
    pricing: { prompt: "0.000005" },
  };
  const openai = { id: "openai/gpt-5.5-pro", pricing: { prompt: "0.00001" } };
  expect(findPricing([opus, openai], "claude-opus-4-6")).toBe(opus);
  expect(findPricing([opus, openai], "gpt-5.5-pro")).toBe(openai);
  expect(findPricing([opus, openai], "anthropic/claude-opus-4.6")).toBe(opus);
  expect(findPricing([opus, openai], "unknown")).toBeUndefined();
  expect(
    findPricing(
      [openai, { ...openai, id: "other/gpt-5.5-pro" }],
      "gpt-5.5-pro",
    ),
  ).toBeUndefined();
});
