// Allowlist of recognized Web Push services. Anything outside this list is
// rejected at submit-time so an attacker cannot turn /api/push/subscribe into
// an SSRF primitive (the stored URL is later POSTed to by webpush.sendNotification).
//
// Mirrors https://github.com/pushpad/known-push-services/blob/master/whitelist

const EXACT_HOSTS = new Set([
  "android.googleapis.com", // Chrome (legacy GCM)
  "fcm.googleapis.com", // Chrome / Edge (Chromium) / FCM Web Push
  "updates.push.services.mozilla.com", // Firefox autopush (production)
  "updates-autopush.stage.mozaws.net", // Firefox autopush (stage)
  "updates-autopush.dev.mozaws.net", // Firefox autopush (dev)
]);

const SUFFIX_HOSTS = [
  ".push.apple.com", // Safari (e.g. web.push.apple.com)
  ".notify.windows.com", // Edge (legacy) / WNS
];

export function isAllowedPushEndpoint(endpoint: string): boolean {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return false;
  }
  if (url.protocol !== "https:") return false;
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (EXACT_HOSTS.has(host)) return true;
  return SUFFIX_HOSTS.some((suffix) => host.endsWith(suffix));
}
