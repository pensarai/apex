import { HOONIFY_BASE_URL } from "../src/core/hoonify";

const apiKey = process.env.HOONIFY_API_KEY?.trim();
if (!apiKey) {
  console.error(
    "HOONIFY_API_KEY is not set. Run this in the same terminal where you exported the key.",
  );
  process.exit(1);
}

function describeShape(value: unknown, depth = 0): unknown {
  if (value === null) return "null";
  if (Array.isArray(value)) {
    return {
      type: "array",
      length: value.length,
      items: value.slice(0, 3).map((item) => describeShape(item, depth + 1)),
    };
  }
  if (typeof value === "object") {
    if (depth > 4) return "object";
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 40)
        .map(([key, item]) => [key, describeShape(item, depth + 1)]),
    );
  }
  return typeof value;
}

try {
  const response = await fetch(`${HOONIFY_BASE_URL}/models`, {
    headers: { Authorization: `Bearer ${apiKey}` },
    signal: AbortSignal.timeout(15_000),
  });
  console.log(
    JSON.stringify({
      status: response.status,
      contentType: response.headers.get("content-type"),
    }),
  );
  if (!response.ok) process.exit(1);
  const body: unknown = await response.json();
  console.log(JSON.stringify({ shape: describeShape(body) }, null, 2));
} catch {
  console.error(
    "Could not read Hoonify's catalog. No credential or response values were printed.",
  );
  process.exit(1);
}
