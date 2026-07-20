import {
  createContext,
  type ReactNode,
  useContext,
  useMemo,
  useState,
} from "react";
import { type SessionInfo, sessions } from "../../core/session";

type SessionContext = {
  active?: SessionInfo;
  load: (id: string) => Promise<SessionInfo | null>;
  create: (name: string, target: string) => Promise<SessionInfo>;
};

const ctx = createContext<SessionContext | null>(null);

type SessionProviderProps = {
  children: ReactNode;
  session?: SessionInfo;
};

export function SessionProvider({ children, session }: SessionProviderProps) {
  const [activeSession, setActiveSession] = useState<SessionInfo | undefined>(
    session,
  );

  const value = useMemo<SessionContext>(
    () => ({
      active: activeSession,
      load: async (id: string) => {
        try {
          const _session = await sessions.get(id);
          setActiveSession(_session);
          return _session;
        } catch (e) {
          // TODO: display error to user
          console.error("Error loading session", e);
          return null;
        }
      },
      create: async (name: string, target: string) => {
        const _session = await sessions.create({
          name: name,
          targets: [target],
        });
        setActiveSession(_session);
        return _session;
      },
    }),
    [activeSession],
  );

  return <ctx.Provider value={value}>{children}</ctx.Provider>;
}
