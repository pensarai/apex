import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ModelInfo } from "../../core/ai";

const FAKE_MODELS: ModelInfo[] = [
  {
    id: "claude-haiku-4-5",
    name: "Claude Haiku 4.5",
    provider: "anthropic",
    contextLength: 200000,
  },
  {
    id: "pensar:anthropic.claude-haiku-4-5-20251001-v1:0",
    name: "Claude Haiku 4.5 (Pensar)",
    provider: "pensar",
    contextLength: 200000,
  },
  {
    id: "gpt-4o-mini",
    name: "GPT-4o Mini",
    provider: "openai",
    contextLength: 128000,
  },
  {
    id: "openrouter:mixtral",
    name: "Mixtral (OpenRouter)",
    provider: "openrouter",
    contextLength: 32000,
  },
  {
    id: "bedrock:titan",
    name: "Titan (Bedrock)",
    provider: "bedrock",
    contextLength: 100000,
  },
  {
    id: "claude-sonnet-4",
    name: "Claude Sonnet 4",
    provider: "anthropic",
    contextLength: 200000,
  },
];

let capturedEffect: (() => void) | null = null;
let capturedSetModel: ((m: ModelInfo) => void) | null = null;
let capturedContextValue: Record<string, unknown> | null = null;

// Spies for assertions
const setModelInternalSpy = vi.fn();
let mockConfigData: Record<string, unknown> = {};
const mockConfigUpdate = vi.fn<
  (data: Record<string, unknown>) => Promise<void>
>(() => Promise.resolve());
const mockWriteErrorLog = vi.fn();
const mockGetAvailableModels = vi.fn<
  (config: Record<string, unknown>) => ModelInfo[]
>(() => []);

vi.mock("react", async () => {
  const actual = await vi.importActual<typeof import("react")>("react");
  return {
    ...actual,
    useState: vi.fn((init: unknown) => {
      // The first useState call with a ModelInfo-shaped object is the model state
      if (
        typeof init === "object" &&
        init !== null &&
        "id" in (init as Record<string, unknown>)
      ) {
        return [init, setModelInternalSpy];
      }
      return [init, vi.fn()];
    }),
    useRef: vi.fn((init: unknown) => ({ current: init })),
    useEffect: vi.fn((cb: () => void) => {
      capturedEffect = cb;
    }),
    useCallback: vi.fn((cb: unknown) => {
      // The first useCallback with a function that takes a ModelInfo is setModel
      // We capture it so tests can invoke it directly
      const fn = cb as (...args: unknown[]) => unknown;
      if (fn.length === 1 && !capturedSetModel) {
        capturedSetModel = fn as (m: ModelInfo) => void;
      }
      return cb;
    }),
    useMemo: vi.fn((factory: () => unknown) => {
      const val = factory();
      // Capture the context value (object with model, setModel, isModelUserSelected, etc.)
      if (
        typeof val === "object" &&
        val !== null &&
        "isModelUserSelected" in (val as Record<string, unknown>)
      ) {
        capturedContextValue = val as Record<string, unknown>;
      }
      return val;
    }),
    useContext: vi.fn(),
    createContext: vi.fn(() => ({
      Provider: ({ children }: { children: unknown }) => children,
    })),
  };
});

vi.mock("./config", () => ({
  useConfig: vi.fn(() => ({
    data: mockConfigData,
    update: mockConfigUpdate,
  })),
}));

vi.mock("../../core/ai/models", () => ({
  AVAILABLE_MODELS: FAKE_MODELS,
}));

vi.mock("../../core/providers/utils", () => ({
  getAvailableModels: (...args: unknown[]) =>
    mockGetAvailableModels(args[0] as Record<string, unknown>),
}));

vi.mock("../../core/logger", () => ({
  writeErrorLog: (...args: unknown[]) => mockWriteErrorLog(...args),
}));

async function renderProvider(configData: Record<string, unknown> = {}) {
  capturedEffect = null;
  capturedSetModel = null;
  capturedContextValue = null;
  setModelInternalSpy.mockClear();
  mockConfigUpdate.mockClear();
  mockWriteErrorLog.mockClear();
  mockConfigData = configData;

  vi.resetModules();

  // Re-apply mocks after resetModules (hoisted mocks are cleared)
  vi.doMock("react", async () => {
    const actual = await vi.importActual<typeof import("react")>("react");
    return {
      ...actual,
      useState: vi.fn((init: unknown) => {
        if (
          typeof init === "object" &&
          init !== null &&
          "id" in (init as Record<string, unknown>)
        ) {
          return [init, setModelInternalSpy];
        }
        return [init, vi.fn()];
      }),
      useRef: vi.fn((init: unknown) => ({ current: init })),
      useEffect: vi.fn((cb: () => void) => {
        capturedEffect = cb;
      }),
      useCallback: vi.fn((cb: unknown) => {
        const fn = cb as (...args: unknown[]) => unknown;
        if (fn.length === 1 && !capturedSetModel) {
          capturedSetModel = fn as (m: ModelInfo) => void;
        }
        return cb;
      }),
      useMemo: vi.fn((factory: () => unknown) => {
        const val = factory();
        if (
          typeof val === "object" &&
          val !== null &&
          "isModelUserSelected" in (val as Record<string, unknown>)
        ) {
          capturedContextValue = val as Record<string, unknown>;
        }
        return val;
      }),
      useContext: vi.fn(),
      createContext: vi.fn(() => ({
        Provider: ({ children }: { children: unknown }) => children,
      })),
    };
  });

  vi.doMock("./config", () => ({
    useConfig: vi.fn(() => ({
      data: mockConfigData,
      update: mockConfigUpdate,
    })),
  }));

  vi.doMock("../../core/ai/models", () => ({
    AVAILABLE_MODELS: FAKE_MODELS,
  }));

  vi.doMock("../../core/providers/utils", () => ({
    getAvailableModels: (...args: unknown[]) =>
      mockGetAvailableModels(args[0] as Record<string, unknown>),
  }));

  vi.doMock("../../core/logger", () => ({
    writeErrorLog: (...args: unknown[]) => mockWriteErrorLog(...args),
  }));

  const mod = await import("./agent");
  mod.AgentProvider({ children: null });

  return {
    runEffect() {
      if (capturedEffect) capturedEffect();
    },
    /** The real setModel callback from the component */
    getSetModel() {
      return capturedSetModel;
    },
    /** The context value produced by useMemo */
    getContextValue() {
      return capturedContextValue;
    },
  };
}

beforeEach(() => {
  mockGetAvailableModels.mockReset();
  mockConfigUpdate.mockReset().mockResolvedValue(undefined);
  mockWriteErrorLog.mockReset();
  setModelInternalSpy.mockClear();
});

describe("AgentProvider model selection", () => {
  describe("restoring a persisted model", () => {
    it("sets the persisted model when it matches an available model", async () => {
      const persistedId = "gpt-4o-mini";
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { runEffect } = await renderProvider({
        selectedModelId: persistedId,
      });
      runEffect();

      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({ id: persistedId }),
      );
      expect(mockConfigUpdate).not.toHaveBeenCalled();
    });

    it("restores the exact ModelInfo object from available models", async () => {
      const persistedId = "pensar:anthropic.claude-haiku-4-5-20251001-v1:0";
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { runEffect } = await renderProvider({
        selectedModelId: persistedId,
      });
      runEffect();

      const calledWith = setModelInternalSpy.mock.calls[0]![0] as ModelInfo;
      expect(calledWith.id).toBe(persistedId);
      expect(calledWith.provider).toBe("pensar");
      expect(calledWith.name).toBe("Claude Haiku 4.5 (Pensar)");
    });

    it("returns early without selecting a smart default", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { runEffect } = await renderProvider({
        selectedModelId: "claude-haiku-4-5",
      });
      runEffect();

      // Only called once — for the persisted model, not a smart default
      expect(setModelInternalSpy).toHaveBeenCalledTimes(1);
      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({ id: "claude-haiku-4-5" }),
      );
    });
  });

  describe("cleaning up a stale persisted model", () => {
    it("clears selectedModelId when persisted model is not in available list", async () => {
      mockGetAvailableModels.mockReturnValue([FAKE_MODELS[0]!]);

      const { runEffect } = await renderProvider({
        selectedModelId: "nonexistent-model-id",
      });
      runEffect();

      expect(mockConfigUpdate).toHaveBeenCalledWith({
        selectedModelId: null,
      });
    });

    it("falls through to smart defaults after clearing stale model", async () => {
      const anthropicOnly = FAKE_MODELS.filter(
        (m) => m.provider === "anthropic",
      );
      mockGetAvailableModels.mockReturnValue(anthropicOnly);

      const { runEffect } = await renderProvider({
        selectedModelId: "nonexistent-model-id",
      });
      runEffect();

      // Cleared the stale model
      expect(mockConfigUpdate).toHaveBeenCalledWith({
        selectedModelId: null,
      });

      // Then selected via smart defaults
      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({ id: "claude-haiku-4-5" }),
      );
    });

    it("logs error when config.update rejects during stale cleanup", async () => {
      const error = new Error("disk full");
      mockConfigUpdate.mockRejectedValue(error);
      mockGetAvailableModels.mockReturnValue([FAKE_MODELS[0]!]);

      const { runEffect } = await renderProvider({
        selectedModelId: "stale-model",
      });
      runEffect();

      await vi.waitFor(() => {
        expect(mockWriteErrorLog).toHaveBeenCalledWith(error, "CONFIG");
      });
    });
  });

  describe("smart default selection (no persisted model)", () => {
    it("selects pensar preferred default when pensar models are available", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { runEffect } = await renderProvider({});
      runEffect();

      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          id: "pensar:anthropic.claude-haiku-4-5-20251001-v1:0",
        }),
      );
    });

    it("selects anthropic preferred default when pensar is unavailable", async () => {
      const noPensar = FAKE_MODELS.filter((m) => m.provider !== "pensar");
      mockGetAvailableModels.mockReturnValue(noPensar);

      const { runEffect } = await renderProvider({});
      runEffect();

      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({ id: "claude-haiku-4-5" }),
      );
    });

    it("selects openai preferred default when pensar and anthropic are unavailable", async () => {
      const openaiAndRest = FAKE_MODELS.filter(
        (m) => m.provider !== "pensar" && m.provider !== "anthropic",
      );
      mockGetAvailableModels.mockReturnValue(openaiAndRest);

      const { runEffect } = await renderProvider({});
      runEffect();

      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({ id: "gpt-4o-mini" }),
      );
    });

    it("selects first openrouter model when higher-priority providers are unavailable", async () => {
      const openrouterAndBedrock = FAKE_MODELS.filter(
        (m) =>
          m.provider !== "pensar" &&
          m.provider !== "anthropic" &&
          m.provider !== "openai",
      );
      mockGetAvailableModels.mockReturnValue(openrouterAndBedrock);

      const { runEffect } = await renderProvider({});
      runEffect();

      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          id: "openrouter:mixtral",
          provider: "openrouter",
        }),
      );
    });

    it("selects first bedrock model when only bedrock is available", async () => {
      const bedrockOnly = FAKE_MODELS.filter((m) => m.provider === "bedrock");
      mockGetAvailableModels.mockReturnValue(bedrockOnly);

      const { runEffect } = await renderProvider({});
      runEffect();

      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          id: "bedrock:titan",
          provider: "bedrock",
        }),
      );
    });

    it("falls back to first model from provider when preferred default is missing", async () => {
      const anthropicNonPreferred: ModelInfo[] = [
        {
          id: "claude-sonnet-4",
          name: "Claude Sonnet 4",
          provider: "anthropic",
          contextLength: 200000,
        },
      ];
      mockGetAvailableModels.mockReturnValue(anthropicNonPreferred);

      const { runEffect } = await renderProvider({});
      runEffect();

      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({ id: "claude-sonnet-4" }),
      );
    });

    it("respects full provider preference order", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { runEffect } = await renderProvider({});
      runEffect();

      const selectedModel = setModelInternalSpy.mock.calls[0]![0] as ModelInfo;
      expect(selectedModel.provider).toBe("pensar");
    });
  });

  describe("isModelUserSelected derivation", () => {
    it("is true when config.data.selectedModelId is a non-empty string", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { getContextValue } = await renderProvider({
        selectedModelId: "claude-haiku-4-5",
      });

      expect(getContextValue()?.isModelUserSelected).toBe(true);
    });

    it("is false when config.data.selectedModelId is null", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { getContextValue } = await renderProvider({
        selectedModelId: null,
      });

      expect(getContextValue()?.isModelUserSelected).toBe(false);
    });

    it("is false when config.data.selectedModelId is undefined", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { getContextValue } = await renderProvider({});

      expect(getContextValue()?.isModelUserSelected).toBe(false);
    });

    it("is false when config.data.selectedModelId is empty string", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { getContextValue } = await renderProvider({
        selectedModelId: "",
      });

      expect(getContextValue()?.isModelUserSelected).toBe(false);
    });
  });

  describe("setModel persists to config", () => {
    it("calls setModelInternal and config.update when invoked", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { getSetModel } = await renderProvider({});
      const setModel = getSetModel();
      expect(setModel).toBeTruthy();

      const newModel: ModelInfo = {
        id: "gpt-4o-mini",
        name: "GPT-4o Mini",
        provider: "openai",
      };

      setModel!(newModel);

      expect(setModelInternalSpy).toHaveBeenCalledWith(newModel);
      expect(mockConfigUpdate).toHaveBeenCalledWith({
        selectedModelId: "gpt-4o-mini",
      });
    });

    it("persists the model id, not the full ModelInfo object", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { getSetModel } = await renderProvider({});
      const setModel = getSetModel()!;

      setModel({
        id: "pensar:anthropic.claude-haiku-4-5-20251001-v1:0",
        name: "Claude Haiku 4.5 (Pensar)",
        provider: "pensar",
        contextLength: 200000,
      });

      expect(mockConfigUpdate).toHaveBeenCalledWith({
        selectedModelId: "pensar:anthropic.claude-haiku-4-5-20251001-v1:0",
      });
    });
  });

  describe("error logging on config write failure", () => {
    it("calls writeErrorLog when config.update rejects in setModel", async () => {
      const error = new Error("write failed");
      mockConfigUpdate.mockRejectedValueOnce(error);
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { getSetModel } = await renderProvider({});
      const setModel = getSetModel()!;

      setModel({
        id: "gpt-4o-mini",
        name: "GPT-4o Mini",
        provider: "openai",
      });

      await vi.waitFor(() => {
        expect(mockWriteErrorLog).toHaveBeenCalledWith(error, "CONFIG");
      });
    });

    it("does not throw when config.update rejects in setModel", async () => {
      mockConfigUpdate.mockRejectedValueOnce(new Error("boom"));
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { getSetModel } = await renderProvider({});
      const setModel = getSetModel()!;

      // Should not throw — error is caught by .catch()
      expect(() =>
        setModel({
          id: "gpt-4o-mini",
          name: "GPT-4o Mini",
          provider: "openai",
        }),
      ).not.toThrow();
    });

    it("calls writeErrorLog when config.update rejects during stale model cleanup", async () => {
      const error = new Error("cleanup failed");
      mockConfigUpdate.mockRejectedValue(error);
      mockGetAvailableModels.mockReturnValue([FAKE_MODELS[0]!]);

      const { runEffect } = await renderProvider({
        selectedModelId: "stale-model",
      });
      runEffect();

      await vi.waitFor(() => {
        expect(mockWriteErrorLog).toHaveBeenCalledWith(error, "CONFIG");
      });
    });
  });

  describe("no model available", () => {
    it("does not change model when getAvailableModels returns empty array", async () => {
      mockGetAvailableModels.mockReturnValue([]);

      const { runEffect } = await renderProvider({});
      runEffect();

      expect(setModelInternalSpy).not.toHaveBeenCalled();
    });

    it("does not attempt to clear persisted model when no models available", async () => {
      mockGetAvailableModels.mockReturnValue([]);

      const { runEffect } = await renderProvider({
        selectedModelId: "some-model",
      });
      runEffect();

      expect(mockConfigUpdate).not.toHaveBeenCalled();
    });

    it("initial model state defaults to AVAILABLE_MODELS[0]", async () => {
      mockGetAvailableModels.mockReturnValue([]);

      const { getContextValue } = await renderProvider({});

      // The useMemo factory receives the model from useState initial value,
      // which is AVAILABLE_MODELS[0] (= FAKE_MODELS[0])
      const ctx = getContextValue();
      expect(ctx?.model).toEqual(
        expect.objectContaining({ id: "claude-haiku-4-5" }),
      );
    });
  });

  describe("edge cases", () => {
    it("handles provider with no entry in PREFERRED_DEFAULTS (bedrock)", async () => {
      const bedrockOnly = FAKE_MODELS.filter((m) => m.provider === "bedrock");
      mockGetAvailableModels.mockReturnValue(bedrockOnly);

      const { runEffect } = await renderProvider({});
      runEffect();

      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({ provider: "bedrock" }),
      );
    });

    it("does not select model when only local provider models are available", async () => {
      const localModel: ModelInfo = {
        id: "custom:my-model",
        name: "Custom Model",
        provider: "local",
      };
      mockGetAvailableModels.mockReturnValue([localModel]);

      const { runEffect } = await renderProvider({});
      runEffect();

      // "local" is not in PROVIDER_PREFERENCE, so nothing is selected
      expect(setModelInternalSpy).not.toHaveBeenCalled();
    });

    it("does not call config.update when persisted model is still available", async () => {
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { runEffect } = await renderProvider({
        selectedModelId: "claude-haiku-4-5",
      });
      runEffect();

      expect(mockConfigUpdate).not.toHaveBeenCalled();
    });

    it("picks preferred default over non-preferred model from same provider", async () => {
      const twoAnthropicModels = FAKE_MODELS.filter(
        (m) => m.provider === "anthropic",
      );
      mockGetAvailableModels.mockReturnValue(twoAnthropicModels);

      const { runEffect } = await renderProvider({});
      runEffect();

      expect(setModelInternalSpy).toHaveBeenCalledWith(
        expect.objectContaining({ id: "claude-haiku-4-5" }),
      );
    });

    it("passes config.data to getAvailableModels", async () => {
      const configData = { anthropicAPIKey: "sk-test" };
      mockGetAvailableModels.mockReturnValue([]);

      const { runEffect } = await renderProvider(configData);
      runEffect();

      expect(mockGetAvailableModels).toHaveBeenCalledWith(configData);
    });

    it("handles persisted model matching when multiple providers have the same model id", async () => {
      // If persisted id matches, the first match in available models is used
      mockGetAvailableModels.mockReturnValue(FAKE_MODELS);

      const { runEffect } = await renderProvider({
        selectedModelId: "claude-sonnet-4",
      });
      runEffect();

      const selected = setModelInternalSpy.mock.calls[0]![0] as ModelInfo;
      expect(selected.id).toBe("claude-sonnet-4");
      expect(selected.provider).toBe("anthropic");
    });
  });
});
