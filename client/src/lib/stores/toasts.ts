import { writable } from "svelte/store";

export type ToastVariant = "info" | "error" | "sign-request";

export interface SignRequestAction {
  actionId: string;
  deepLink: string;
  source: string;
  endpointLabel?: string;
  endpointAddress?: string;
  passkeyLabel?: string;
}

export interface Toast {
  id: string;
  variant: ToastVariant;
  message: string;
  /** Present for sign-request toasts */
  action?: SignRequestAction;
  /** Auto-dismiss after this many ms (not used for sign-request) */
  dismissAfterMs?: number;
}

let nextId = 0;

export const toasts = writable<Toast[]>([]);

export function addToast(toast: Omit<Toast, "id">): string {
  const id = `toast-${++nextId}`;
  toasts.update((t) => [...t, { ...toast, id }]);

  if (toast.dismissAfterMs) {
    setTimeout(() => removeToast(id), toast.dismissAfterMs);
  }

  return id;
}

export function removeToast(id: string): void {
  toasts.update((t) => t.filter((toast) => toast.id !== id));
}

/** Remove all toasts associated with a specific action ID */
export function clearAction(actionId: string): void {
  toasts.update((t) => t.filter((toast) => toast.action?.actionId !== actionId));
}

/** Convenience: show an error toast (auto-dismiss after 5s) */
export function toastError(message: string): string {
  return addToast({ variant: "error", message, dismissAfterMs: 5000 });
}

/** Convenience: show an info toast (auto-dismiss after 3s) */
export function toastInfo(message: string): string {
  return addToast({ variant: "info", message, dismissAfterMs: 3000 });
}
