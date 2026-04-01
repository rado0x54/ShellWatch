import { writable } from "svelte/store";

/** Base path injected by the server via config.js / environment. */
export const basePath = writable("");
