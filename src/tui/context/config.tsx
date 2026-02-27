import {
  useState,
  createContext,
  useContext,
  type ReactNode,
  useMemo,
} from "react";
import {
  get as getConfig,
  update as updateConfig,
  type Config,
} from "../../core/config";

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

  const value = useMemo(
    () => ({
      data: appConfig,
      update: async (newConfig: Partial<Config>) => {
        await updateConfig(newConfig);
        setAppConfig({
          ...appConfig,
          ...newConfig,
        });
      },
      reload: async () => {
        const freshConfig = await getConfig();
        setAppConfig(freshConfig);
      },
    }),
    [appConfig],
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
