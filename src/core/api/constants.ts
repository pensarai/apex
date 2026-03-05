export const PENSAR_API_BASE_URL = "https://api.console.pensar.dev";
export const PENSAR_CONSOLE_BASE_URL = "https://console.pensar.dev";

export function getPensarApiUrl(config?: {
  pensarApiUrl?: string | null;
}): string {
  return (
    config?.pensarApiUrl || process.env.PENSAR_API_URL || PENSAR_API_BASE_URL
  );
}

export function getPensarConsoleUrl(): string {
  return process.env.PENSAR_CONSOLE_URL || PENSAR_CONSOLE_BASE_URL;
}
