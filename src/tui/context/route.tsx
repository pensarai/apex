import {
  createContext,
  type ReactNode,
  useContext,
  useMemo,
  useState,
} from "react";
import type { SessionConfig } from "../../core/session";

export type RoutePath =
  | "home"
  | "help"
  | "pentest"
  | "thorough"
  | "operator"
  | "chat"
  | "dns"
  | "config"
  | "models"
  | "providers"
  | "disclosure"
  | "theme"
  | "auth"
  | "credits";

export interface WebCommandOptions {
  auto?: boolean;
  target?: string;
  name?: string;
  swarm?: boolean;
  mode?: "plan" | "manual" | "auto";
  requireApproval?: boolean;
  authUrl?: string;
  authUser?: string;
  authPass?: string;
  authInstructions?: string;
  hosts?: string[];
  ports?: number[];
  strict?: boolean;
  headersMode?: "none" | "default" | "custom";
  customHeaders?: Record<string, string>;
  model?: string;
  prompt?: string;
  threatModel?: string;
}

export type Route =
  | {
      type: "base";
      path: RoutePath;
      options?: WebCommandOptions;
    }
  | {
      type: "pentest";
      sessionId?: string;
      /** When sessionId is omitted, create a new session from these fields */
      targets?: string[];
      sessionConfig?: SessionConfig;
      /** If true, open an auto-mode session in operator mode */
      openAsOperator?: boolean;
    }
  | {
      type: "operator";
      sessionId?: string;
      initialMessage?: string;
      initialConfig?: {
        requireApproval?: boolean;
        target?: string;
        operatorMode?: import("../../core/operator").OperatorMode;
        sandbox?: boolean;
        taskDriven?: boolean;
      };
      /** Skill to automatically submit on mount */
      initialSkill?: { slug: string; args?: Record<string, string> };
      /** Opaque value used to force a fresh remount (e.g. Date.now()) */
      nonce?: number;
    };

type RouteContext = {
  data: Route;
  navigate: (route: Route) => void;
};

const ctx = createContext<RouteContext | null>(null);

type RouteProviderProps = {
  children: ReactNode;
};

export function RouteProvider({ children }: RouteProviderProps) {
  const [route, setRoute] = useState<Route>({
    type: "base",
    path: "home",
  });

  const value = useMemo(
    () => ({
      data: route,
      navigate: (newRoute: Route) => {
        console.log("navigating to:", newRoute);
        setRoute(newRoute);
      },
    }),
    [route],
  );

  return <ctx.Provider value={value}>{children}</ctx.Provider>;
}

export const useRoute = () => {
  const route = useContext(ctx);
  if (!route) {
    throw new Error("useRoute must be called within a RouteProvider");
  }
  return route;
};

export const useRouteData = <T extends Route["type"]>(type: T) => {
  const route = useRoute();
  return route.data as Extract<Route, { type: typeof type }>;
};
