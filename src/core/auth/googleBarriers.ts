const SOFTWARE_BROWSER_MARKERS = [
  "this browser or app may not be secure",
  "couldn't sign you in",
  "automated software",
];

export type GoogleBarrier = "blocked_software_browser" | null;

export function classifyGoogleBarrier(pageText: string): GoogleBarrier {
  const lower = pageText.toLowerCase();
  if (SOFTWARE_BROWSER_MARKERS.some((marker) => lower.includes(marker))) {
    return "blocked_software_browser";
  }
  return null;
}
