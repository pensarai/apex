import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { Session } from "../../core/session";

type SessionContext = {
    active?: Session.SessionInfo;
    load: (id: string) => Promise<Session.SessionInfo | null>;
    create: (name: string, target: string) => Promise<Session.SessionInfo>;
};


const ctx = createContext<SessionContext | null>(null);

type SessionProviderProps = {
    children: ReactNode;
    session?: Session.SessionInfo;
};

export function SessionProvider({ children, session }: SessionProviderProps) {
    const [activeSession, setActiveSession] = useState<Session.SessionInfo | undefined>(session);

    const value = useMemo<SessionContext>(() => ({
        active: activeSession,
        load: async (id: string) => {
            try {
                const _session = await Session.get(id);
                setActiveSession(_session);
                return _session;
            } catch(e) {
                // TODO: display error to user
                console.error("Error loading session", e);
                return null;
            }
        },
        create: async (name: string, target: string) => {
            const _session = await Session.create({ name: name, targets: [target] });
            setActiveSession(_session);
            return _session;
        }
    }), [activeSession]);

    return <ctx.Provider value={value}>{ children }</ctx.Provider>
}

export const useSession = () => {
    const session = useContext(ctx);
    if(!session) throw new Error("useSession must be called within a SessionProvider");
    return session;
}