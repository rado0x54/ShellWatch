declare global {
  interface Window {
    __BASE_PATH__?: string;
  }
}

/** Returns the configured base path (e.g. "/shellwatch"), or empty string if none. */
export const basePath: string = window.__BASE_PATH__ ?? "";
