import { readFile, realpath, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { hasToolCall, type ModelMessage, stepCountIs } from "ai";
import { DEFAULT_LANCE_BUDGET } from "../../../src/core/agents/lanceBudget";
import {
  ALL_TOOL_NAMES,
  ASK_USER_QUESTIONS_TOOL_NAME,
  PLAN_MODE_TOOL_NAMES,
  SKILL_TOOL_NAMES,
} from "../../../src/core/agents/offSecAgent";
import { buildAuthConfig, normalizeStepUsage } from "../../../src/core/ai";
import { createOffensiveSecurityAgentClient } from "../../../src/core/api";
import { getSavedReasoning } from "../../../src/core/cli/reasoning";
import { config } from "../../../src/core/config";
import { CredentialManager } from "../../../src/core/credentials";
import { AgentEventBus } from "../../../src/core/eventBus";
import {
  formatParseError,
  parseHeaderLine,
  parseHeaderList,
} from "../../../src/core/http/parse";
import { renderHeaderValue } from "../../../src/core/http/types";
import {
  ApprovalGate,
  createInitialOperatorState,
  OPERATOR_MODE_CYCLE,
} from "../../../src/core/operator";
import { planFilePath, readPlan } from "../../../src/core/plan";
import {
  getAvailableModels,
  getDefaultModelForConfig,
  getSavedModelForConfig,
} from "../../../src/core/providers/utils";
import {
  normalizeMessages,
  type SessionInfo,
  sessions,
} from "../../../src/core/session";
import {
  readExecutionMetrics,
  writeExecutionMetrics,
} from "../../../src/core/session/execution-metrics";
import { convertModelMessagesToUI } from "../../../src/core/session/persistence";
import {
  accumulateSessionTokens,
  EMPTY_SESSION_TOKEN_USAGE,
} from "../../../src/core/session/usage";
import { createSkillsRegistry } from "../../../src/core/skills";
import { buildInteractiveThreatModelPrompt } from "../../../src/core/skills/builtins";
import type { DisplayMessage } from "../../../src/tui/components/agent-display";
import {
  recoverAbortedTranscript,
  rewriteToolResultOutput,
} from "../../../src/tui/components/operator-dashboard/conversation";
import { markInFlightToolsErrored } from "../../../src/tui/components/operator-dashboard/display-state";
import {
  buildOperatorSystemPrompt,
  resolveActiveFindingPolicy,
  resolveOperatorAgentMode,
  resolveOperatorFindingPolicy,
  routeCommand,
} from "../../../src/tui/components/operator-dashboard/logic";
import {
  bindOperatorRunEvents,
  createDisplayEventHandlers,
  createRunEventProjections,
} from "../../../src/tui/components/operator-dashboard/run-events";
import { RunTraceSession } from "../../../src/tui/components/operator-dashboard/run-tracing";
import {
  createSubagentSessionHelpers,
  createSubagentStore,
  loadSubagentSessionsFromDisk,
  markSubagentsInterrupted,
} from "../../../src/tui/components/operator-dashboard/subagent-state";
import { updateWorkflowDataMessage } from "../../../src/tui/components/operator-dashboard/workflow-data";
import { operatorArguments } from "./arguments";
import type {
  OperatorAction,
  OperatorLaunch,
  OperatorMessage,
  OperatorMode,
  OperatorSnapshot,
} from "./contract";
import type { OperatorFrame } from "./live";
import { selectedTools } from "./tools";

function wireMessage(m: DisplayMessage): OperatorMessage {
  return {
    ...m,
    createdAt: new Date(m.createdAt).toISOString(),
    content:
      typeof m.content === "string" ? m.content : JSON.stringify(m.content),
  };
}

type HostOptions = {
  cwd: () => string;
  requireAcceptance: () => void;
  emit: (frame: OperatorFrame) => void;
};
type AgentClient = ReturnType<typeof createOffensiveSecurityAgentClient>;

class OperatorHost {
  constructor(private options: HostOptions) {}
  private session?: SessionInfo;
  private workingDirectory = "";
  private history: ModelMessage[] = [];
  private messages: DisplayMessage[] = [];
  private readonly agents = createSubagentStore();
  private readonly agentHelpers = createSubagentSessionHelpers(
    this.agents.setState,
  );
  private readonly skills = createSkillsRegistry();
  private readonly gate = new ApprovalGate({ requireApproval: true });
  private readonly command = { cancel: () => false };
  private model?: string;
  private modelOverride?: string;
  private globalModelAtStart?: string | null;
  private status: OperatorSnapshot["status"] = "idle";
  private mode: OperatorMode = "manual";
  private error?: string;
  private plan: string | null = null;
  private reviewPlan = false;
  private approvedPlan: string | null = null;
  private rejectedPlan = false;
  private questions?: OperatorSnapshot["questions"];
  private queue: { id: string; text: string; prompt: string }[] = [];
  private usage = { ...EMPTY_SESSION_TOKEN_USAGE };
  private context?: {
    usedTokens: number;
    contextLimit: number;
    modelId: string;
  };
  private revision = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private disposed = false;
  private changing = false;
  private applyingAction = false;
  private client?: AgentClient;
  private turn?: Promise<void>;
  private modelLoading?: string;
  private resumedPlan = false;
  private unsubscribeAgents?: () => void;
  private watcher?: string;
  private baseRevision = 0;
  private baseSession?: string;
  private sentMessages = new Map<string, DisplayMessage[]>();
  private snapshotMeta() {
    const s = this.session;
    return {
      revision: ++this.revision,
      sessionId: s?.id,
      name: s?.name,
      target: s?.targets[0],
      mode: this.mode,
      status:
        this.status === "running" && this.gate.getPendingApprovals().length
          ? ("waiting" as const)
          : this.status,
      model: this.model,
      modelLoading: this.modelLoading,
      strike: !!s?.config?.operatorSettings?.strikeMode,
      lance: !!s?.config?.operatorSettings?.lanceMode,
      error: this.error,
      approvals: this.gate
        .getPendingApprovals()
        .map(({ id, toolName, args, reasoning }) => ({
          id,
          toolName,
          args,
          reasoning,
        })),
      questions: this.client ? undefined : this.questions,
      queue: this.queue.map(({ id, text }) => ({ id, text })),
      headers: Object.entries(s?.config?.headers ?? {}).map(
        ([name, value]) => ({
          name,
          displayValue: renderHeaderValue(name, value, false),
        }),
      ),
      plan: this.plan,
      reviewPlan: !this.client && this.reviewPlan,
      usage: {
        input: this.usage.inputTokens,
        output: this.usage.outputTokens,
        context: this.context?.usedTokens,
        limit: this.context?.contextLimit,
      },
    };
  }
  private catalog() {
    return this.skills.list().map((e) => ({
      slug: e.slug,
      name: e.manifest.name,
      description: e.manifest.description,
    }));
  }
  private snapshot(): OperatorSnapshot {
    return {
      ...this.snapshotMeta(),
      skills: this.catalog(),
      messages: this.messages.map(wireMessage),
      subagents: [...this.agents.getSnapshot().values()].map((a) => ({
        id: a.id,
        name: a.name,
        status: a.status,
        input: a.input,
        messages: a.messages.map(wireMessage),
      })),
    };
  }
  private patch(key: string, messages: DisplayMessage[]) {
    const previous = this.sentMessages.get(key) ?? [];
    let from = 0;
    while (
      from < previous.length &&
      from < messages.length &&
      messages[from] === previous[from]
    )
      from++;
    this.sentMessages.set(key, [...messages]);
    return { from, messages: messages.slice(from).map(wireMessage) };
  }
  private watch({ key }: { key: string }) {
    this.watcher = key;
    const state = this.snapshot();
    this.baseRevision = state.revision;
    this.baseSession = state.sessionId;
    this.sentMessages.clear();
    this.sentMessages.set("", [...this.messages]);
    for (const agent of this.agents.getSnapshot().values())
      this.sentMessages.set(agent.id, [...agent.messages]);
    return state;
  }
  private publish = () => {
    if (!this.watcher || this.timer || this.disposed) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      if (!this.watcher || this.disposed) return;
      const state = this.snapshotMeta();
      const switched = state.sessionId !== this.baseSession;
      if (switched) this.sentMessages.clear();
      const frame: OperatorFrame = {
        baseRevision: this.baseRevision,
        state,
        transcript: this.patch("", this.messages),
        ...(switched && { skills: this.catalog() }),
        subagents: [...this.agents.getSnapshot().values()].map((a) => ({
          id: a.id,
          name: a.name,
          status: a.status,
          input: a.input,
          transcript: this.patch(a.id, a.messages),
        })),
      };
      this.baseRevision = state.revision;
      this.baseSession = state.sessionId;
      this.options.emit(frame);
    }, 60);
  };
  private reset(session: SessionInfo, mode: OperatorMode, model?: string) {
    this.session = session;
    this.mode = mode;
    this.gate.updateConfig({ requireApproval: mode === "manual" });
    this.modelOverride = model;
    this.model = model;
    this.error = undefined;
    this.history = [];
    this.messages = [];
    this.queue = [];
    this.questions = undefined;
    this.status = "idle";
    this.agents.setState(new Map());
    this.plan = readPlan(session.rootPath);
    this.approvedPlan = mode === "plan" ? null : this.plan;
    this.rejectedPlan = false;
    this.resumedPlan = false;
    this.reviewPlan = false;
    const metrics = readExecutionMetrics(session.rootPath);
    this.usage = metrics?.tokenUsage ?? { ...EMPTY_SESSION_TOKEN_USAGE };
    this.context = metrics?.contextUsage;
  }
  private async switchSession<T>(operation: () => Promise<T>) {
    this.options.requireAcceptance();
    if (
      this.disposed ||
      this.changing ||
      this.applyingAction ||
      this.client ||
      this.questions ||
      this.reviewPlan
    )
      throw new Error("Finish or cancel the current operator turn first.");
    this.changing = true;
    try {
      return await operation();
    } finally {
      this.changing = false;
    }
  }
  start = async (input: OperatorLaunch) =>
    this.switchSession(async () => {
      const cfg = await config.get();
      const currentModel = this.resolveModel(cfg, input.model);
      let headers = input.headers;
      if (input.headerLines !== undefined) {
        const parsed = parseHeaderList(input.headerLines);
        if (!parsed.ok)
          throw new Error(parsed.error.map(formatParseError).join("\n"));
        headers = Object.fromEntries(
          parsed.value.map(({ name, value }) => [name, value]),
        );
      }
      const strikeMode = input.strikeMode ?? cfg.strikeMode ?? false;
      const lanceMode = input.lanceMode ?? cfg.lanceMode ?? false;
      const mode = input.mode ?? "manual";
      if (!OPERATOR_MODE_CYCLE.includes(mode))
        throw new Error("Invalid operator mode.");
      const cwd = this.options.cwd();
      await this.skills.load({ projectRoot: cwd });
      const session = await sessions.create({
        name: input.name || (input.prompt ? undefined : "Operator"),
        targets: input.target ? [input.target] : [],
        model: currentModel,
        authConfig: buildAuthConfig(cfg),
        userMessage: input.displayPrompt ?? input.prompt,
        config: {
          sessionType: "web-app",
          mode: "operator",
          operatorSettings: {
            initialMode: mode,
            requireApproval: mode === "manual",
            enableSuggestions: true,
            strikeMode,
            lanceMode,
            lanceBudget: cfg.lanceBudget ?? DEFAULT_LANCE_BUDGET,
            findingPolicy: resolveOperatorFindingPolicy({
              resuming: false,
              strikeMode,
              lanceMode,
              persistedDefault: cfg.findingPolicy,
            }),
          },
          agentCwd: input.sandbox ? undefined : (input.codebasePath ?? cwd),
          codebasePath: input.sandbox ? undefined : (input.codebasePath ?? cwd),
          taskDriven: input.taskDriven,
          scopeConstraints: input.scopeConstraints,
          authenticationInstructions: input.authenticationInstructions,
          enumerateSubdomains: input.enumerateSubdomains,
          prompt: input.guidance,
          authCredentials: input.authCredentials?.map((credential) => ({
            ...credential,
            id: crypto.randomUUID(),
          })),
          headers,
          promptInjectionLibrarySource: input.promptInjectionLibrarySource,
        },
      });
      this.workingDirectory = cwd;
      this.reset(session, mode, input.model);
      this.model = currentModel;
      this.globalModelAtStart = cfg.selectedModelId;
      if (input.skill) {
        const { content } = await this.skills.readSkillContent(input.skill);
        const prompt =
          input.skill === "threat-model"
            ? buildInteractiveThreatModelPrompt({
                outputPath: resolve(
                  cwd,
                  input.skillOutput || "threat-model.md",
                ),
                codebasePath: cwd,
                skillContent: content,
              })
            : `<skill name="prompt-injection">\nWorking directory: ${cwd}\nTarget: ${input.target ?? ""}\nLibrary: ${input.promptInjectionLibrarySource ?? ""}\n\n${content}\n</skill>`;
        this.run(prompt, `/${input.skill}`);
      } else if (input.prompt) this.run(input.prompt, input.displayPrompt);
      this.publish();
      return { ...this.snapshot(), sessionId: session.id };
    });
  private resolveModel(
    cfg: Awaited<ReturnType<typeof config.get>>,
    override?: string,
  ) {
    const selected = getSavedModelForConfig(cfg);
    if (override) {
      if (
        selected?.id === override ||
        getAvailableModels(cfg).some((m) => m.id === override)
      )
        return override;
      throw new Error(
        `Model ${override} is unavailable. Choose a configured model in Settings.`,
      );
    }
    const model = selected ?? getDefaultModelForConfig(cfg);
    if (!model)
      throw new Error(
        "Configure an AI provider in Settings before starting an operator turn.",
      );
    return model.id;
  }
  private resume = async ({ id }: { id: string }) => {
    this.options.requireAcceptance();
    if (id === this.session?.id) return this.snapshot();
    return this.switchSession(async () => {
      if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(id))
        throw new Error("Invalid session ID");
      const session = await sessions.get(id);
      const credentials = session.config?.authCredentials;
      if (credentials) {
        session.credentialManager = new CredentialManager();
        for (const entry of Array.isArray(credentials)
          ? credentials
          : [credentials])
          session.credentialManager.addFromAuthCredentials(entry);
      }
      const state = await sessions.loadOperatorState(id);
      const cwd = session.config?.agentCwd ?? this.options.cwd();
      await this.skills.load({ projectRoot: cwd });
      this.workingDirectory = cwd;
      const storedMode =
        state?.mode ?? session.config?.operatorSettings?.initialMode;
      this.reset(
        session,
        storedMode === "auto" || storedMode === "plan" ? storedMode : "manual",
      );
      if (!state && sessions.hasOperatorState(session))
        throw new Error("Could not read the saved operator transcript.");
      this.resumedPlan = this.mode === "plan" && !!this.plan;
      if (state?.messages?.length) {
        this.history = normalizeMessages(
          sessions.getResumeMessages(state.messages),
        );
        this.messages = convertModelMessagesToUI(state.messages);
      }
      this.agents.setState(loadSubagentSessionsFromDisk(session.rootPath));
      this.publish();
      return this.snapshot();
    });
  };
  private run(prompt: string | null, label?: string) {
    const session = this.session;
    if (!session || this.client || this.disposed)
      throw new Error("The operator cannot start another turn now.");
    const client = createOffensiveSecurityAgentClient();
    this.client = client;
    this.status = "running";
    this.error = undefined;
    this.turn = this.execute(session, client, prompt, label);
    this.publish();
  }
  private async execute(
    session: SessionInfo,
    client: AgentClient,
    prompt: string | null,
    label?: string,
  ) {
    const previous = this.history;
    const transcriptPath = join(session.rootPath, "messages.json");
    const display = createDisplayEventHandlers({
      updateMessages: (fn) => {
        this.messages = fn(this.messages);
        this.publish();
      },
      setThinking: () => {},
      setError: (e) => {
        this.error = e;
        this.publish();
      },
    });
    const projections = createRunEventProjections({
      display,
      subagents: this.agentHelpers,
      updateWorkflowData: (fn) => {
        this.messages = updateWorkflowDataMessage(this.messages, fn);
        this.publish();
      },
      onModelLoading: (model) => {
        this.modelLoading = model ?? undefined;
        this.publish();
      },
      clearSubagentSessions: () => this.agents.setState(new Map()),
      questions: {
        onAsked: (id, questions) => {
          this.questions = { toolCallId: id, questions };
          this.publish();
        },
        onCleared: () => {
          this.questions = undefined;
          this.publish();
        },
      },
      onPlanSubmitted: () => {
        this.resumedPlan = false;
        this.reviewPlan = true;
        this.publish();
      },
    });
    const bus = new AgentEventBus();
    const current = () =>
      this.client === client && !this.disposed && this.status !== "stopping";
    const unbind = bindOperatorRunEvents(bus, {
      isCurrent: current,
      handlers: projections.handlers,
    });
    const recordUsage = (
      inputTokens: number,
      outputTokens: number,
      cacheReadTokens = 0,
      cacheWriteTokens = 0,
    ) => {
      this.usage = accumulateSessionTokens(this.usage, {
        inputTokens,
        outputTokens,
        cacheReadTokens,
        cacheWriteTokens,
      });
      writeExecutionMetrics({
        sessionRootPath: session.rootPath,
        tokenUsage: this.usage,
        contextUsage: this.context,
      });
      this.publish();
    };
    const trace = new RunTraceSession(bus, {
      isCurrent: current,
      recordTokenUsage: recordUsage,
    });
    try {
      const cfg = await config.get();
      if (!current()) return;
      if (this.modelOverride && this.globalModelAtStart !== cfg.selectedModelId)
        this.modelOverride = undefined;
      const model = this.resolveModel(cfg, this.modelOverride);
      const persistedSession = await sessions.get(session.id);
      if (!current()) return;
      session.config = persistedSession.config;
      session.name = persistedSession.name;
      this.model = model;
      const saved = session.config?.operatorSettings;
      const lance = !!saved?.lanceMode;
      const agentMode = resolveOperatorAgentMode(
        this.mode,
        !!saved?.strikeMode,
        lance,
      );
      const policy = resolveActiveFindingPolicy(
        agentMode,
        saved?.findingPolicy ?? "native",
      );
      const target = session.targets[0];
      const system = lance
        ? undefined
        : buildOperatorSystemPrompt(
            target,
            createInitialOperatorState(this.mode, this.mode === "manual"),
            agentMode,
            {
              requireApproval: this.mode === "manual",
              sandboxMode: !session.config?.agentCwd,
              skillsCatalog: this.skills.buildCatalog(),
              planFilePath: planFilePath(session.rootPath),
              existingPlanContent:
                agentMode === "plan" && this.rejectedPlan ? this.plan : null,
              approvedPlanContent:
                agentMode !== "plan" ? this.approvedPlan : null,
              taskDriven: session.config?.taskDriven,
              findingPolicy: policy,
            },
          );
      if (prompt !== null) {
        this.history = normalizeMessages([
          ...this.history,
          { role: "user", content: prompt },
        ]);
        this.messages.push({
          role: "user",
          content: label ?? prompt,
          createdAt: new Date(),
        });
        await writeFile(transcriptPath, JSON.stringify(this.history, null, 2));
        this.publish();
      }
      await trace.tryAttach(session);
      if (!current()) return;
      const savedReasoning = session.config?.modelReasoning;
      const reasoning =
        cfg.modelReasoning?.[model] !== undefined
          ? getSavedReasoning(model, cfg)
          : savedReasoning?.model === model
            ? savedReasoning.setting
            : getSavedReasoning(model, cfg);
      const result = await client.run({
        session,
        system,
        prompt: prompt ?? "",
        messages: this.history,
        model,
        target,
        mode: agentMode,
        activeTools: selectedTools(session, [
          ...(agentMode === "plan" ? PLAN_MODE_TOOL_NAMES : ALL_TOOL_NAMES),
          ...SKILL_TOOL_NAMES,
        ]),
        lance: lance
          ? {
              interactive: true,
              budget: saved?.lanceBudget ?? DEFAULT_LANCE_BUDGET,
            }
          : undefined,
        stopWhen: [
          stepCountIs(10000),
          hasToolCall(ASK_USER_QUESTIONS_TOOL_NAME),
        ],
        findingPolicy: policy,
        approvalGate: this.gate,
        commandCancelHandle: this.command,
        eventBus: bus,
        skillsRegistry: this.skills,
        authConfig: buildAuthConfig(cfg),
        reasoning,
        promptInjectionLibrarySource:
          session.config?.promptInjectionLibrarySource,
        surfaceIntegrationEnabled: cfg.surfaceIntegrationEnabled,
        onStepFinish: (event) => {
          if (!current()) return;
          const step = normalizeStepUsage(event);
          if (step.inputTokens && event.contextWindow)
            this.context = {
              usedTokens: step.inputTokens,
              contextLimit: event.contextWindow,
              modelId: model,
            };
          recordUsage(
            step.inputTokens,
            step.outputTokens,
            step.cacheReadTokens,
            step.cacheWriteTokens,
          );
        },
      });
      if (!current()) return;
      const persisted = await sessions.loadOperatorState(session.id);
      this.history = normalizeMessages(
        sessions.getResumeMessages(
          persisted?.messages ?? [
            ...this.history,
            ...(await result.streamResult.response).messages,
          ],
        ),
      );
      if (result.lance && result.lance.outcome !== "awaiting_input")
        this.messages.push({
          role: "system",
          createdAt: new Date(),
          content: `Lance: ${result.lance.outcome}. ${result.lance.reason}`,
        });
    } catch (e) {
      if (current()) {
        this.error = e instanceof Error ? e.message : String(e);
        this.history = previous;
        this.questions = undefined;
        this.queue = [];
        this.messages = markInFlightToolsErrored(this.messages, this.error);
        try {
          await writeFile(transcriptPath, JSON.stringify(previous, null, 2));
        } catch (writeError) {
          this.error += ` · Transcript rollback failed: ${writeError}`;
        }
      }
    } finally {
      unbind();
      display.finish();
      if (this.status === "stopping") {
        this.history = recoverAbortedTranscript({
          rootPath: session.rootPath,
          conversation: this.history,
          partialText: display.getPartialText(),
          displayMessages: this.messages,
        });
        this.messages = markInFlightToolsErrored(this.messages, "Interrupted");
        this.messages.push({
          role: "system",
          content: "Agent stopped.",
          createdAt: new Date(),
        });
        this.agents.setState(markSubagentsInterrupted);
      }
      display.dispose();
      await trace.cleanupRun();
      this.plan = readPlan(session.rootPath);
      this.modelLoading = undefined;
      this.status = this.questions || this.reviewPlan ? "waiting" : "idle";
      this.client = undefined;
      this.turn = undefined;
      if (this.status === "idle" && !this.disposed && !this.error) {
        const next = this.queue.shift();
        if (next) this.run(next.prompt, next.text);
      }
      this.publish();
    }
  }
  private async modeChange(mode: OperatorMode) {
    const session = this.session;
    if (!session) throw new Error("No operator session.");
    const updated = await sessions.updateOperatorSettings(session.id, {
      initialMode: mode,
      requireApproval: mode === "manual",
    });
    session.config = updated.config;
    this.gate.updateConfig({ requireApproval: mode === "manual" });
    this.mode = mode;
    if (mode === "plan") {
      this.approvedPlan = null;
      this.rejectedPlan = false;
      this.resumedPlan = false;
    }
  }
  private async cancel() {
    this.queue = [];
    this.reviewPlan = false;
    if (this.questions && !this.client && this.session) {
      this.history = rewriteToolResultOutput(
        this.history,
        this.questions.toolCallId,
        { answers: [], skipped: true, aborted: true },
      );
      await writeFile(
        join(this.session.rootPath, "messages.json"),
        JSON.stringify(this.history, null, 2),
      );
    }
    this.questions = undefined;
    if (this.client) {
      this.status = "stopping";
      this.client.abort();
      this.gate.denyAll();
    } else this.status = "idle";
    this.publish();
  }
  private submit(text: string, label?: string) {
    if (!text.trim()) throw new Error("Enter a message.");
    if (this.questions || this.reviewPlan)
      throw new Error("Resolve the pending review first.");
    if (this.client) {
      this.queue.push({
        id: crypto.randomUUID(),
        text: label ?? text,
        prompt: text,
      });
      this.gate.denyAll();
    } else this.run(text, label);
  }
  private async action({
    sessionId,
    action,
  }: {
    sessionId: string;
    action: OperatorAction;
  }) {
    this.options.requireAcceptance();
    const session = this.session;
    if (this.changing || !session || sessionId !== session.id)
      throw new Error("The active operator session changed.");
    switch (action.type) {
      case "send":
        this.submit(action.text.trim());
        break;
      case "skill": {
        if (session.config?.operatorSettings?.lanceMode)
          throw new Error("Lance accepts direct objectives only.");
        if (
          session.config?.operatorSettings?.strikeMode &&
          ["pentest", "threat-model"].includes(action.slug)
        )
          throw new Error("This skill needs standard operator mode.");
        const { content } = await this.skills.readSkillContent(action.slug);
        if (action.autopilot) await this.modeChange("auto");
        const prompt =
          action.slug === "threat-model"
            ? buildInteractiveThreatModelPrompt({
                outputPath: resolve(this.workingDirectory, "threat-model.md"),
                codebasePath: this.workingDirectory,
                skillContent: content,
              })
            : `<skill name="${action.slug}">\nWorking directory: ${this.workingDirectory}\n\n${content}\n</skill>`;
        this.submit(
          action.arguments?.length
            ? `${prompt}\nOperator input: ${action.arguments.join(" ")}`
            : prompt,
          `/${action.slug}`,
        );
        break;
      }
      case "mode":
        if (!OPERATOR_MODE_CYCLE.includes(action.mode))
          throw new Error("Invalid operator mode.");
        if (this.client && (action.mode === "plan" || this.mode === "plan"))
          throw new Error(
            "Finish the current turn before switching plan tools.",
          );
        if (this.questions || this.reviewPlan)
          throw new Error(
            "Resolve the current operator review before changing mode.",
          );
        if (
          this.mode === "plan" &&
          this.plan &&
          !this.approvedPlan &&
          !this.resumedPlan &&
          action.mode !== "plan"
        ) {
          this.reviewPlan = true;
          this.status = "waiting";
        } else {
          await this.modeChange(action.mode);
          if (action.mode === "auto")
            for (const approval of this.gate.getPendingApprovals())
              this.gate.approve(approval.id);
        }
        break;
      case "approval":
        if (!this.gate.getPendingApprovals().some((a) => a.id === action.id))
          throw new Error("This approval is no longer pending.");
        if (action.decision === "auto") {
          await this.modeChange("auto");
          for (const p of this.gate.getPendingApprovals())
            this.gate.approve(p.id);
        } else if (action.decision === "approve") this.gate.approve(action.id);
        else this.gate.deny(action.id);
        break;
      case "cancel":
        await this.cancel();
        break;
      case "cancel-command":
        if (!this.command.cancel()) throw new Error("No command is running.");
        break;
      case "queue": {
        const i = this.queue.findIndex((q) => q.id === action.id);
        if (i === -1) throw new Error("The queued message already ran.");
        const [message] = this.queue.splice(i, 1);
        if (action.operation === "send-now") {
          const turn = this.turn;
          const rest = this.queue;
          await this.cancel();
          await turn;
          this.queue = rest;
          this.run(message.prompt, message.text);
        }
        break;
      }
      case "plan":
        if (this.client || !this.reviewPlan)
          throw new Error("There is no plan awaiting review.");
        if (action.approve) {
          this.plan = readPlan(session.rootPath);
          if (!this.plan?.trim()) throw new Error("The plan file is empty.");
          await this.modeChange("manual");
          this.approvedPlan = this.plan;
          this.reviewPlan = false;
          this.run("Proceed with the approved plan.");
        } else {
          this.rejectedPlan = true;
          this.reviewPlan = false;
          this.status = "idle";
        }
        break;
      case "answer": {
        if (this.client || this.questions?.toolCallId !== action.toolCallId)
          throw new Error("This question is no longer pending.");
        const next = rewriteToolResultOutput(this.history, action.toolCallId, {
          answers: action.answers,
          skipped: action.skip,
        });
        if (next === this.history)
          throw new Error("The question is missing from the saved transcript.");
        await writeFile(
          join(session.rootPath, "messages.json"),
          JSON.stringify(next, null, 2),
        );
        this.history = next;
        this.questions = undefined;
        this.run(null);
        break;
      }
      case "headers": {
        const routed = routeCommand(action.command, () => null);
        if (routed.type !== "headers")
          throw new Error("Invalid headers command");
        const op = routed.op;
        if (op.kind === "invalid") throw new Error(op.reason);
        const headers = { ...session.config?.headers };
        if (op.kind === "list") {
          this.messages.push({
            role: "system",
            content:
              Object.entries(headers)
                .map(
                  ([name, value]) =>
                    `${name}: ${renderHeaderValue(name, value, op.showSecrets)}`,
                )
                .join("\n") || "No session headers.",
            createdAt: new Date(),
          });
          break;
        }
        if (op.kind === "add") {
          const entry = parseHeaderLine(op.line);
          if (!entry.ok) throw new Error(formatParseError(entry.error));
          const key = Object.keys(headers).find(
            (h) => h.toLowerCase() === entry.value.name.toLowerCase(),
          );
          if (key && !op.allowOverwrite)
            throw new Error(
              `Header "${key}" already exists. Use /headers set to replace it.`,
            );
          if (key) delete headers[key];
          headers[entry.value.name] = entry.value.value;
        } else if (op.kind === "remove") {
          const key = Object.keys(headers).find(
            (h) => h.toLowerCase() === op.name.toLowerCase(),
          );
          if (!key) throw new Error(`No header named "${op.name}".`);
          delete headers[key];
        }
        session.config = (
          await sessions.updateSessionHeaders(
            session.id,
            op.kind === "clear" ? {} : headers,
          )
        ).config;
        break;
      }
      case "open-folder": {
        const { Utils } = await import("electrobun/bun");
        if (!Utils.openPath(session.rootPath))
          throw new Error("Could not open the session folder.");
        break;
      }
    }
    this.publish();
    return this.snapshot();
  }
  private async screenshot({
    sessionId,
    toolCallId,
    agentId,
  }: {
    sessionId: string;
    toolCallId: string;
    agentId?: string;
  }) {
    if (sessionId !== this.session?.id || !this.session)
      throw new Error("The active session changed.");
    const messages = agentId
      ? this.agents.getSnapshot().get(agentId)?.messages
      : this.messages;
    const result = messages?.find(
      (m) =>
        m.toolCallId === toolCallId &&
        m.toolName === "browser_screenshot" &&
        m.status === "completed",
    )?.result;
    if (
      !result ||
      typeof result !== "object" ||
      !("path" in result) ||
      typeof result.path !== "string"
    )
      throw new Error("Screenshot unavailable.");
    const root = await realpath(this.session.rootPath);
    const file = await realpath(result.path);
    const rel = relative(root, file);
    if (
      !rel ||
      rel.startsWith("..") ||
      isAbsolute(rel) ||
      !basename(file).toLowerCase().endsWith(".png")
    )
      throw new Error("The screenshot is outside the session folder.");
    return `data:image/png;base64,${(await readFile(file)).toString("base64")}`;
  }
  requests = {
    operatorArguments: ({ command }: { command: string }) =>
      operatorArguments(command, this.options.cwd()),
    operatorState: () => this.snapshot(),
    operatorWatch: (p: { key: string }) => this.watch(p),
    operatorUnwatch: ({ key }: { key: string }) => {
      if (this.watcher === key) {
        this.watcher = undefined;
        this.sentMessages.clear();
      }
    },
    operatorStart: this.start,
    operatorResume: this.resume,
    operatorAction: async (input: {
      sessionId: string;
      action: OperatorAction;
    }) => {
      if (this.applyingAction)
        throw new Error("Another operator action is still pending.");
      this.applyingAction = true;
      try {
        return await this.action(input);
      } finally {
        this.applyingAction = false;
      }
    },
    operatorScreenshot: (input: {
      sessionId: string;
      toolCallId: string;
      agentId?: string;
    }) => this.screenshot(input),
  };
  init() {
    this.gate.on("approval-needed", this.publish);
    this.gate.on("approval-resolved", this.publish);
    this.unsubscribeAgents = this.agents.subscribe(this.publish);
  }
  dispose() {
    this.disposed = true;
    this.unsubscribeAgents?.();
    this.sentMessages.clear();
    if (this.timer) clearTimeout(this.timer);
    this.gate.denyAll();
    this.gate.removeAllListeners();
    this.client?.abort();
  }
}

export function createOperatorHost(options: HostOptions) {
  const host = new OperatorHost(options);
  host.init();
  return host;
}
