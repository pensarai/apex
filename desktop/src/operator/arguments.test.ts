import { describe, expect, it } from "vitest";
import { splitCommand } from "../commands";
import { operatorArguments } from "./arguments";

describe("operator slash commands", () => {
  it("preserves quoted literals, empty fields and escaped whitespace without shell expansion", () => {
    expect(
      splitCommand(
        '/o --name="Quarterly $HOME" --auth-pass \'\' --target QA\\ host --header "X: @literal"',
      ),
    ).toEqual([
      "/o",
      "--name=Quarterly $HOME",
      "--auth-pass",
      "",
      "--target",
      "QA host",
      "--header",
      "X: @literal",
    ]);
    expect(() => splitCommand('/o --auth-pass "do-not-echo')).toThrow(
      /^Close the quoted command argument\.$/,
    );
  });
  it("prefills all operator flags without creating a session or running inference", () => {
    expect(
      operatorArguments(
        '/o -n "Review API" -t https://test.invalid:8443 -m plan --model fixture --hosts api.invalid --ports 8080 --strict --auth-url https://test.invalid/login --auth-user tester --auth-pass secret --auth-instructions "use login" --header "X-Trace: abc" --sandbox --task-driven',
        "/work",
      ),
    ).toEqual({
      name: "Review API",
      target: "https://test.invalid:8443",
      model: "fixture",
      mode: "plan",
      sandbox: true,
      taskDriven: true,
      headers: { "X-Trace": "abc" },
      scopeConstraints: {
        allowedHosts: ["api.invalid", "test.invalid"],
        allowedPorts: [8080, 8443],
        strictScope: true,
      },
      authCredentials: [
        {
          username: "tester",
          password: "secret",
          loginUrl: "https://test.invalid/login",
        },
      ],
      authenticationInstructions: "use login",
    });
    expect(
      operatorArguments("/operator --autopilot --headers none", "/work"),
    ).toMatchObject({ mode: "auto", headers: {} });
    expect(() =>
      operatorArguments("/operator --ports 100000", "/work"),
    ).toThrow("Allowed ports");
    expect(() => operatorArguments("/operator --invalid", "/work")).toThrow();
  });
  it("preserves threat-model and prompt-injection inputs on their short aliases", () => {
    expect(
      operatorArguments(
        '/tm -o "reports/threat model.md" --model fixture',
        "/work",
      ),
    ).toMatchObject({
      skill: "threat-model",
      skillOutput: "reports/threat model.md",
      model: "fixture",
    });
    expect(
      operatorArguments(
        '/pi --target test.invalid --library "my payloads"',
        "/work",
      ),
    ).toMatchObject({
      skill: "prompt-injection",
      target: "test.invalid",
      promptInjectionLibrarySource: "/work/my payloads",
    });
  });
});
