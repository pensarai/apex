export const PENSAR_API_BASE_URL = "https://api.pensar.dev";
export const PENSAR_GATEWAY_BASE_URL = "https://gateway.pensar.dev";
export const PENSAR_CONSOLE_BASE_URL = "https://console.pensar.dev";

export function getPensarApiUrl(): string {
  return PENSAR_API_BASE_URL;
}

export function getPensarGatewayUrl(): string {
  return process.env.PENSAR_GATEWAY_URL || PENSAR_GATEWAY_BASE_URL;
}

export function getPensarConsoleUrl(): string {
  return process.env.PENSAR_CONSOLE_URL || PENSAR_CONSOLE_BASE_URL;
}
