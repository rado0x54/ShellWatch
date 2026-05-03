// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import { writable } from "svelte/store";

/** Whether self-registration is enabled, injected by the server via config.js. */
export const selfRegistrationEnabled = writable(false);
