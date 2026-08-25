import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";
import { config as _config } from "../../core/config";
import type { Config } from "../../core/config/config";

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
