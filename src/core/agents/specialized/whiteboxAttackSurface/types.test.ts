import { describe, expect, it } from "vitest";
import { EndpointSchema } from "./types";

describe("EndpointSchema.method tolerance", () => {
  it("accepts a plain HTTP method string", () => {
    const parsed = EndpointSchema.parse({
      method: "GET",
      path: "/dashboard",
      file: "src/app/page.tsx",
    });
    expect(parsed.method).toBe("GET");
  });

  it("accepts an array of methods and joins them into a single string", () => {
    // The model routinely emits multi-method endpoints as an array
    // (e.g. ["GET","POST"]). Before this tolerance, that rejected the whole
    // submit_results payload and the entire recon was silently discarded.
    const parsed = EndpointSchema.parse({
      method: ["GET", "POST"],
      path: "/api/users/:id",
      file: "src/routes/users.ts",
    });
    expect(parsed.method).toBe("GET, POST");
  });

  it("still rejects a method that is neither string nor string array", () => {
    const result = EndpointSchema.safeParse({
      method: 42,
      path: "/x",
      file: "f.ts",
    });
    expect(result.success).toBe(false);
  });
});

describe("EndpointSchema.pentestObjectives tolerance", () => {
  it("defaults to an empty array when omitted", () => {
    const parsed = EndpointSchema.parse({
      method: "GET",
      path: "/x",
      file: "f.ts",
    });
    expect(parsed.pentestObjectives).toEqual([]);
  });

  it("wraps a lone string objective into a one-element array", () => {
    const parsed = EndpointSchema.parse({
      method: "GET",
      path: "/x",
      file: "f.ts",
      pentestObjectives: "Test for IDOR by enumerating user IDs",
    });
    expect(parsed.pentestObjectives).toEqual([
      "Test for IDOR by enumerating user IDs",
    ]);
  });

  it("passes through an array of objectives unchanged", () => {
    const parsed = EndpointSchema.parse({
      method: "GET",
      path: "/x",
      file: "f.ts",
      pentestObjectives: ["a", "b"],
    });
    expect(parsed.pentestObjectives).toEqual(["a", "b"]);
  });
});
