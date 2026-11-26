import type { LanceBudget } from "../../../src/core/agents/lanceBudget";
import type { ReasoningSetting } from "../../../src/core/ai";
import type { ProviderType } from "../../../src/core/providers";

export type SettingsTab =
  | "Providers"
  | "Models"
  | "Account"
  | "Advanced"
  | "Appearance";
export type KeyProvider = Exclude<ProviderType, "local" | "pensar">;
export type ServiceKey =
  | "daytonaAPIKey"
  | "daytonaOrgId"
  | "runloopAPIKey"
  | "braveAPIKey"
  | "exaAPIKey";
export type Appearance = {
  theme: string;
  mode: "dark" | "light" | "auto";
  transparent: boolean;
  obfuscate: boolean;
};
export type Advanced = {
  mode: "standard" | "strike" | "lance";
  findingPolicy: "native" | "external";
  budget: LanceBudget;
  surface: boolean;
  goals?: boolean;
};
export type SettingsModel = {
  id: string;
  name: string;
  provider: string;
  reasoning?: ReasoningSetting;
  choices: ReasoningSetting[];
};
export type AccountState =
  | {
      stage: "idle" | "loading" | "connected";
      workspace?: string;
      billingReady?: boolean;
      canSwitch?: boolean;
      storedCredentials?: boolean;
      balance?: number;
    }
  | { stage: "authorize" | "create"; url: string; code?: string }
  | { stage: "choose"; workspaces: { id: string; name: string }[] }
  | { stage: "error"; message: string };
export interface SettingsSnapshot {
  providers: {
    id: ProviderType;
    name: string;
    configured: boolean;
    keySource?: "saved" | "environment";
    environmentVariable?: string;
  }[];
  hasProvider: boolean;
  local: { url: string; name: string };
  custom: {
    id: string;
    name: string;
    definition: string;
    fromEnvironment: boolean;
  }[];
  catalogError?: string;
  models: SettingsModel[];
  selected?: string;
  recent: string[];
  advanced: Advanced;
  appearance: Appearance;
  headers: { name: string; display: string }[];
  services: Record<ServiceKey, boolean>;
}
export type SettingsChange =
  | { kind: "provider"; id: KeyProvider; key: string | null }
  | { kind: "custom"; id: string; definition: string | null }
  | { kind: "local"; url: string; name: string }
  | { kind: "model"; id: string; reasoning?: ReasoningSetting }
  | { kind: "advanced"; value: Advanced }
  | { kind: "service"; id: ServiceKey; value: string | null }
  | { kind: "header"; name: string; value: string | null }
  | { kind: "appearance"; value: Appearance };
export type AccountAction =
  | "inspect"
  | "login"
  | "cancel"
  | "switch"
  | "disconnect"
  | "billing";
type Call<P, R> = { params: P; response: R };
export type SettingsRequests = {
  desktopSettings: Call<void, SettingsSnapshot>;
  changeSettings: Call<SettingsChange, SettingsSnapshot>;
  desktopAppearance: Call<void, Appearance>;
  accountAction: Call<
    { action: AccountAction } | { action: "select"; id: string },
    AccountState
  >;
  accountStatus: Call<void, AccountState>;
  desktopBalance: Call<void, { balance: number; workspace: string } | null>;
};
