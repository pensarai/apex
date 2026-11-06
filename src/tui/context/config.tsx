import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { config as _config } from "../../core/config";
import type { Config } from "../../core/config/config";
import { discoverOllama } from "../../core/ollama";

type ConfigContext = {
  data: Config;
  update: (newConfig: Partial<Config>) => Promise<void>;
  reload: () => Promise<void>;
};

const ctx = createContext<ConfigContext | null>(null);

type ConfigProviderProps = {
  children: ReactNode;
  config: Config;
};

export function ConfigProvider({ children, config }: ConfigProviderProps) {
  const [appConfig, setAppConfig] = useState<Config>(config);

  useEffect(() => {
    const controller = new AbortController();
    const refresh = async () => {
      const ollama = await discoverOllama(controller.signal);
      if (controller.signal.aborted) return;
      setAppConfig((current) =>
        JSON.stringify(current.ollama) === JSON.stringify(ollama)
          ? current
          : { ...current, ollama },
      );
    };
    void refresh();
    const interval = setInterval(refresh, 5_000);
    return () => {
      controller.abort();
      clearInterval(interval);
    };
  }, []);

  const update = useCallback(async (newConfig: Partial<Config>) => {
    await _config.update(newConfig);
    setAppConfig((current) => ({
      ...current,
      ...newConfig,
    }));
  }, []);

  const reload = useCallback(async () => {
    const freshConfig = await _config.get();
    setAppConfig(freshConfig);
  }, []);

  const value = useMemo(
    () => ({
      data: appConfig,
      update,
      reload,
    }),
    [appConfig, reload, update],
  );

  return <ctx.Provider value={value}>{children}</ctx.Provider>;
}

export const useConfig = () => {
  const config = useContext(ctx);
  if (!config) {
    throw new Error("useConfig must be called within a ConfigProvider");
  }
  return config;
};
