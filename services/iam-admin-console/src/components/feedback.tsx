import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

/**
 * App-wide feedback: toast notifications for the outcome of an action and a
 * confirmation dialog for destructive ones (replaces window.confirm, which
 * can't be styled, blocks the page, and is suppressed by some browsers).
 * Both are provided once at the app root; pages just call useToast() /
 * useConfirm().
 */

type ToastKind = "success" | "error" | "info";

interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastApi {
  success: (message: string) => void;
  error: (message: string) => void;
  info: (message: string) => void;
}

export interface ConfirmOptions {
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
}

type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>;
/** Like ConfirmFn, but the dialog also asks for a reason: resolves to the trimmed reason, or null if cancelled. */
type ConfirmReasonFn = (options: ConfirmOptions) => Promise<string | null>;

const ToastContext = createContext<ToastApi | null>(null);
const ConfirmContext = createContext<ConfirmFn | null>(null);
const ConfirmReasonContext = createContext<ConfirmReasonFn | null>(null);

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside <FeedbackProvider>");
  return ctx;
}

export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error("useConfirm must be used inside <FeedbackProvider>");
  return ctx;
}

/**
 * Confirmation that also asks for a reason (spec 13.2: privileged actions need confirmation, reason and audit). The confirm button
 * stays disabled until a reason is typed.
 */
export function useConfirmReason(): ConfirmReasonFn {
  const ctx = useContext(ConfirmReasonContext);
  if (!ctx) throw new Error("useConfirmReason must be used inside <FeedbackProvider>");
  return ctx;
}

const TOAST_MS: Record<ToastKind, number> = { success: 4000, info: 4000, error: 7000 };

export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const id = nextId.current++;
      setToasts((prev) => [...prev, { id, kind, message }]);
      window.setTimeout(() => dismiss(id), TOAST_MS[kind]);
    },
    [dismiss],
  );

  const toastApi = useMemo<ToastApi>(
    () => ({
      success: (m) => push("success", m),
      error: (m) => push("error", m),
      info: (m) => push("info", m),
    }),
    [push],
  );

  const [dialog, setDialog] = useState<(ConfirmOptions & { withReason: boolean; resolve: (reason: string | null) => void }) | null>(null);

  const confirm = useCallback<ConfirmFn>(
    (options) => new Promise<boolean>((resolve) => setDialog({ ...options, withReason: false, resolve: (r) => resolve(r !== null) })),
    [],
  );

  const confirmReason = useCallback<ConfirmReasonFn>(
    (options) => new Promise<string | null>((resolve) => setDialog({ ...options, withReason: true, resolve })),
    [],
  );

  function close(ok: boolean, reason = "") {
    dialog?.resolve(ok ? reason.trim() : null);
    setDialog(null);
  }

  return (
    <ToastContext.Provider value={toastApi}>
      <ConfirmContext.Provider value={confirm}>
        <ConfirmReasonContext.Provider value={confirmReason}>
        {children}

        <div className="toast-stack" aria-live="polite">
          {toasts.map((t) => (
            <div key={t.id} className={`toast toast--${t.kind}`} role={t.kind === "error" ? "alert" : "status"}>
              <span className="toast__message">{t.message}</span>
              <button type="button" className="toast__close" aria-label="Dismiss" onClick={() => dismiss(t.id)}>
                ×
              </button>
            </div>
          ))}
        </div>

        {dialog && <ConfirmDialog options={dialog} withReason={dialog.withReason} onClose={close} />}
        </ConfirmReasonContext.Provider>
      </ConfirmContext.Provider>
    </ToastContext.Provider>
  );
}

function ConfirmDialog({ options, withReason, onClose }: { options: ConfirmOptions; withReason: boolean; onClose: (ok: boolean, reason?: string) => void }) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const [reason, setReason] = useState("");
  const canConfirm = !withReason || reason.trim().length > 0;

  useEffect(() => {
    // Default focus on Cancel so a stray Enter never confirms a destructive action.
    cancelRef.current?.focus();
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" onMouseDown={() => onClose(false)}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <h3 id="confirm-title" className="modal__title">
          {options.title}
        </h3>
        <div className="modal__body">{options.message}</div>
        {withReason && (
          <label className="login-form__field" style={{ marginTop: 12 }}>
            <span>Reason (required, kept in the audit log)</span>
            <textarea value={reason} maxLength={500} rows={3} onChange={(e) => setReason(e.target.value)} placeholder="For example: laptop reported lost" />
          </label>
        )}
        <div className="modal__actions">
          <button ref={cancelRef} type="button" className="btn-secondary" onClick={() => onClose(false)}>
            {options.cancelLabel ?? "Cancel"}
          </button>
          <button type="button" className={options.danger ? "btn-solid-danger" : ""} disabled={!canConfirm} onClick={() => onClose(true, reason)}>
            {options.confirmLabel ?? "Confirm"}
          </button>
        </div>
      </div>
    </div>
  );
}
