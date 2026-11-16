import { describe, expect, it } from "vitest";
import type { OperatorSnapshot } from "../operator/contract";
import {
  latestSessionReply,
  needsSessionInput,
  sessionUnread,
} from "./session-status";

const snapshot = (
  overrides: Partial<OperatorSnapshot> = {},
): OperatorSnapshot => ({
  revision: 1,
  status: "idle",
  mode: "manual",
  strike: false,
  lance: false,
  messages: [],
  subagents: [],
  approvals: [],
  queue: [],
  skills: [],
  headers: [],
  plan: null,
  reviewPlan: false,
  usage: { input: 0, output: 0 },
  ...overrides,
});

describe("session sidebar notifications", () => {
  it("needs input for approvals, questions and plan review, but not an empty question batch", () => {
    expect(
      needsSessionInput(
        snapshot({
          approvals: [
            { id: "approval", toolName: "execute_command", args: {} },
          ],
        }),
      ),
    ).toBe(true);
    expect(
      needsSessionInput(
        snapshot({
          questions: {
            toolCallId: "question",
            questions: [
              {
                id: "q",
                header: "Scope",
                question: "Which scope?",
                options: [],
              },
            ],
          },
        }),
      ),
    ).toBe(true);
    expect(needsSessionInput(snapshot({ reviewPlan: true }))).toBe(true);
    expect(
      needsSessionInput(
        snapshot({ questions: { toolCallId: "question", questions: [] } }),
      ),
    ).toBe(false);
    expect(needsSessionInput(snapshot({ status: "running" }))).toBe(false);
  });

  it("marks new background replies unread and clears them only when viewed", () => {
    expect(sessionUnread("", "reply", false, false)).toBe(true);
    expect(sessionUnread("reply", "reply-more", false, false)).toBe(true);
    expect(sessionUnread("reply", "reply", true, false)).toBe(true);
    expect(sessionUnread("reply", "reply", true, true)).toBe(false);
    expect(sessionUnread("reply", "reply-more", false, true)).toBe(false);
    expect(sessionUnread("reply", "reply", false, false)).toBe(false);
    expect(sessionUnread("", "", false, false)).toBe(false);
  });

  it("ignores user, tool and empty assistant updates when tracking unread messages", () => {
    const first = snapshot({
      messages: [
        {
          role: "assistant",
          content: "Found the endpoint",
          createdAt: "first",
        },
      ],
    });
    const reply = latestSessionReply(first);
    const withTools = snapshot({
      messages: [
        ...first.messages,
        { role: "tool", content: "Tool output", createdAt: "second" },
        { role: "user", content: "Continue", createdAt: "third" },
        { role: "assistant", content: "", createdAt: "fourth" },
      ],
    });
    expect(latestSessionReply(withTools)).toBe(reply);
    expect(
      latestSessionReply(
        snapshot({
          messages: [
            { ...first.messages[0], content: "Found the endpoint and route" },
          ],
        }),
      ),
    ).not.toBe(reply);
    expect(
      latestSessionReply(
        snapshot({
          messages: [
            ...first.messages,
            { ...first.messages[0], createdAt: "next-turn" },
          ],
        }),
      ),
    ).not.toBe(reply);
  });
});
