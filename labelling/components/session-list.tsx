"use server";

import { listSessions } from "@/core/agent/sessions";
import Link from "next/link";

export default async function SessionList() {
  const sessions = listSessions();
  return (
    <div className="shrink-0 border border-zinc-700 rounded-md p-4 w-fit h-fit max-h-full overflow-y-auto mr-4">
      <div className="flex flex-col gap-2">
        {sessions.map((session) => (
          <Link href={`/${session}`} key={session}>
            <div key={session} className="text-lg font-bold">
              {session}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
