export type Bindings = Env & {
  // Local development only, from .dev.vars. See .dev.vars.example.
  DEV_BYPASS_ACCESS?: string;
};

export type AppEnv = {
  Bindings: Bindings;
  Variables: { userEmail: string | undefined };
};
