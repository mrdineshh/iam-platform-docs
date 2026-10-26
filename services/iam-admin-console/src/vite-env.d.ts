/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AUTH_SVC_URL?: string;
  readonly VITE_TENANT_SVC_URL?: string;
  readonly VITE_POLICY_SVC_URL?: string;
  readonly VITE_ROOT_DOMAIN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
