import assert from "node:assert/strict";
import {
  createSubagentSessionHelpers,
  createSubagentStore,
  markSubagentsInterrupted,
} from "../../src/tui/components/operator-dashboard/subagent-state";

const subscription = process.argv[2] ?? "counts";
assert.ok(subscription === "counts" || subscription === "full");

// Callback counts, not timings: assertions deliberately inspect every live snapshot.
for (const agents of [1, 8, 32]) {
  const store = createSubagentStore();
  const helpers = createSubagentSessionHelpers(store.setState);
  const fullMap = { lifecycle: 0, stream: 0 };
  const dashboard = { lifecycle: 0, stream: 0 };
  let phase: keyof typeof fullMap = "lifecycle";
  const expectedText = new Map<string, string>();
  const unsubscribeFull = store.subscribe(() => {
    fullMap[phase]++;
    for (const session of store.getSnapshot().values()) {
      assert.equal(
        session.messages[0]?.content ?? "",
        expectedText.get(session.id) ?? "",
      );
    }
  });
  const subscribeDashboard =
    subscription === "counts" ? store.subscribeCounts : store.subscribe;
  const unsubscribeDashboard = subscribeDashboard(() => {
    dashboard[phase]++;
  });
  for (let agent = 0; agent < agents; agent++) {
    helpers.spawnSession(`agent-${agent}`);
  }

  phase = "stream";
  for (let delta = 0; delta < 100; delta++) {
    for (let agent = 0; agent < agents; agent++) {
      const id = `agent-${agent}`;
      const text = `${id}:${delta}\n`;
      expectedText.set(id, (expectedText.get(id) ?? "") + text);
      helpers.appendText(id, text);
    }
  }
  for (let agent = 0; agent < agents; agent++) {
    const id = `agent-${agent}`;
    helpers.addStreamingToolCall(id, `tool-${id}`, "execute_command");
  }
  let command = "";
  for (let delta = 0; delta < 20; delta++) {
    const text = `part-${delta} `;
    command += text;
    for (let agent = 0; agent < agents; agent++) {
      const id = `agent-${agent}`;
      helpers.appendToolCallDelta(
        id,
        `tool-${id}`,
        `${delta === 0 ? '{"command":"' : ""}${text}${delta === 19 ? '"}' : ""}`,
      );
      assert.equal(
        store.getSnapshot().get(id)?.messages[1].args?.command,
        command,
      );
    }
  }
  for (let agent = 0; agent < agents; agent++) {
    const id = `agent-${agent}`;
    helpers.addToolCall(id, `tool-${id}`, "execute_command", { command });
    helpers.updateToolResult(id, `tool-${id}`, `result-${id}`);
  }

  phase = "lifecycle";
  for (let agent = 0; agent < agents - 1; agent++) {
    helpers.completeSession(
      `agent-${agent}`,
      agent % 2 === 0 ? "completed" : "failed",
    );
  }
  store.setState(markSubagentsInterrupted);
  for (let agent = 0; agent < agents; agent++) {
    const id = `agent-${agent}`;
    const session = store.getSnapshot().get(id);
    assert.equal(
      session?.status,
      agent === agents - 1
        ? "cancelled"
        : agent % 2 === 0
          ? "completed"
          : "failed",
    );
    assert.equal(session?.messages[1].status, "completed");
    assert.equal(session?.messages[1].result, `result-${id}`);
  }
  store.setState(new Map());
  unsubscribeFull();
  unsubscribeDashboard();

  assert.deepEqual(fullMap, {
    lifecycle: 2 * agents + 1,
    stream: 123 * agents,
  });
  assert.deepEqual(dashboard, {
    lifecycle: fullMap.lifecycle,
    stream: subscription === "counts" ? 0 : fullMap.stream,
  });
  console.log(JSON.stringify({ agents, subscription, fullMap, dashboard }));
}
