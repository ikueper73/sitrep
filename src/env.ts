export type Bindings = Env & {
  // Optional NVD API key (secret): raises NVD's rate limit from 5 to 50 requests / 30 s.
  NVD_API_KEY?: string;
  // Local development only, from .dev.vars. See .dev.vars.example.
  DEV_BYPASS_ACCESS?: string;
};

export type AppEnv = {
  Bindings: Bindings;
  Variables: { userEmail: string | undefined };
};
