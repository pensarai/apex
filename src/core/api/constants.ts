export const PENSAR_API_BASE_URL = "https://api.console.pensar.dev";

export function getPensarApiUrl(config?: {
  pensarApiUrl?: string | null;
}): string {
  return (
    config?.pensarApiUrl ||
    process.env.PENSAR_API_URL ||
    PENSAR_API_BASE_URL
  );
}
