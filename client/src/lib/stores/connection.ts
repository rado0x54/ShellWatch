import { writable } from "svelte/store";

/** Base path injected by the server via config.js / environment. */
export const basePath = writable("");

/** Whether self-registration is enabled, injected by the server via config.js. */
export const selfRegistrationEnabled = writable(false);
