// Split out from actions.ts: a "use server" file may only export async
// functions (Next.js requirement -- every other export becomes a server
// action reference). initialLoginFormState is a plain object, so it has to
// live here instead. Found live: docker logs showed
// `Error: A "use server" file can only export async functions, found
// object.` when this was still in actions.ts -- logged in docs/DECISIONS.md.
export interface LoginFormState {
  error?: string;
  errorCode?: string;
}

export const initialLoginFormState: LoginFormState = {};

// Input/output for precheckAction (actions.ts) -- a plain async function the
// password step calls directly (not via a <form action>), so these live
// here rather than inline, same "use server" export-shape constraint as
// LoginFormState above.
export interface PrecheckActionInput {
  tenantOverride: string | null;
  email: string;
  password: string;
}

export type PrecheckActionResult =
  | { ok: true; mfaRequired: false }
  | { ok: true; mfaRequired: true; enrollmentRequired: true; totpSecret?: string; provisioningUri?: string }
  | { ok: true; mfaRequired: true; enrollmentRequired: false }
  | { ok: false; error: string; errorCode?: string };
