import { useState, createContext, useContext, type ReactNode, useMemo } from "react";


export type RoutePath =
    "home"
    | "help"
    | "pentest"
    | "thorough"
    | "dns"
    | "config"
    | "sessions"
    | "models"
    | "disclosure";

export type Route = 
    {
        type: "base",
        path: RoutePath
    }
  | {
        type: "session",
        sessionId: string
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