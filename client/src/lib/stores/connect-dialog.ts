// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
/**
 * The endpoint picker behind the sidebar's "Connect" (and the guest-access
 * page's "Share access"): one dialog, rendered once by the root layout, that
 * any view can open.
 *
 * - `connect`: every endpoint with Connect and Share access.
 * - `share`: the same list with Share access only.
 */
import { writable } from "svelte/store";

export type ConnectDialogMode = "connect" | "share";

export const connectDialog = writable<ConnectDialogMode | null>(null);

/**
 * True while the dialog shows the share form for an endpoint (including a
 * freshly created link, which is shown exactly once): a page change must
 * not close it then.
 */
export const connectDialogSharing = writable(false);

export function openConnectDialog(mode: ConnectDialogMode = "connect"): void {
  connectDialog.set(mode);
}

export function closeConnectDialog(): void {
  connectDialog.set(null);
}
