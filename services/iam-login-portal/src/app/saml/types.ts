// Same "use server" export-shape constraint as ../login/types.ts.
export interface SamlLoginFormState {
  error?: string;
  errorCode?: string;
  autoPost?: {
    acsUrl: string;
    samlResponse: string;
    relayState: string | null;
  };
}

export const initialSamlLoginFormState: SamlLoginFormState = {};
