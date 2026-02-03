import { useEffect, useState } from "react";
import type { Session } from "../../core/session"
import { useSession } from "../context/session";

interface SessionDisplayProps {
    sessionId: string
}

export function SessionDisplay (props: SessionDisplayProps) {
    const { sessionId } = props;
    const _session = useSession();
    const [session, setSession] = useState<Session.SessionInfo>();

    const loadSession = async (id: string) => {
        const sessionData = await _session.load(sessionId);
        if(sessionData) {
            setSession(sessionData);
        }
        // else handle error
    }

    useEffect(() => {
        loadSession(sessionId);
    }, [props]);

    return (
        <box
         justifyContent="space-between"
         flexDirection="column"
        >
        <box
        alignItems="center"
        justifyContent="center"
        flexDirection="column"
        width="100%"
        maxHeight="100%"
        flexGrow={1}
        overflow="hidden"
        gap={1}
        >
            <text>
                Enter a target domain or domains.
            </text>
            <text>
                Use `@` to point to an engagement config file to load all settings, scope, and rules of engagement. 
            </text>

        </box>
        <input/>
        </box>
    )
}