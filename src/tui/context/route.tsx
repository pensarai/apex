import { useState, createContext, useContext, type ReactNode, useMemo } from "react";


export type RoutePath =
    "home"
    | "help"
    | "pentest"
    | "thorough"
    | "web"
    | "operator"
    | "chat"
    | "dns"
    | "config"
    | "models"
    | "providers"
    | "disclosure"
    | "resume";

export interface WebCommandOptions {
    auto?: boolean;
    target?: string;
    name?: string;
    swarm?: boolean;
    mode?: 'plan' | 'manual' | 'auto';
    tier?: number;
    authUrl?: string;
    authUser?: string;
    authPass?: string;
    authInstructions?: string;
    hosts?: string[];
    ports?: number[];
    strict?: boolean;
    headersMode?: 'none' | 'default' | 'custom';
    customHeaders?: Record<string, string>;
    model?: string;
}

export type Route =
    {
        type: "base",
        path: RoutePath,
        options?: WebCommandOptions
    }
  | {
        type: "session",
        sessionId: string,
        /** If true, load existing session state without starting a new pentest */
        isResume?: boolean
    };


type RouteContext = {
    data: Route;
    navigate: (route: Route) => void;
};

const ctx = createContext<RouteContext | null>(null);

type RouteProviderProps = {
    children: ReactNode;
}

export function RouteProvider({ children }: RouteProviderProps) {
    const [route, setRoute] = useState<Route>({
        type: "base",
        path: "home"
    });

    const value = useMemo(() => ({
        data: route,
        navigate: (newRoute: Route) => {
            console.log("navigating to:", newRoute);
            setRoute(newRoute);
        }
    }), [route]);

   return <ctx.Provider value={value}>{ children }</ctx.Provider>
}

export const useRoute = () => {
    const route = useContext(ctx);
    if(!route) {
        throw new Error("useRoute must be called within a RouteProvider");
    }
    return route;
};

export const useRouteData = <T extends Route['type']>(type: T) => {
    const route = useRoute();
    return route.data as Extract<Route, {type: typeof type}>
};