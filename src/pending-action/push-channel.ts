import webpush from "web-push";
import type { PushSubscriptionRepository } from "../db/repositories/push-subscription-repo.js";
import type { NotificationChannel } from "./dispatcher.js";
import type { PendingAction } from "./types.js";

export interface PushChannelParams {
  pushSubRepo: PushSubscriptionRepository;
  vapid: { subject: string; publicKey: string; privateKey: string };
  log?: { info(msg: string): void; warn(msg: string): void };
}

export class PushChannel implements NotificationChannel {
  readonly name = "web-push";
  private repo: PushSubscriptionRepository;
  private log?: PushChannelParams["log"];

  constructor(params: PushChannelParams) {
    this.repo = params.pushSubRepo;
    this.log = params.log;
    webpush.setVapidDetails(params.vapid.subject, params.vapid.publicKey, params.vapid.privateKey);
  }

  async send(action: PendingAction, deepLink: string): Promise<void> {
    const subscriptions = this.repo.findByAccountId(action.accountId);
    if (subscriptions.length === 0) return;

    const payload = JSON.stringify({
      title:
        action.type === "webauthn-sign"
          ? "Passkey Signature Requested"
          : "SSH Key Approval Requested",
      body: this.buildBody(action),
      actionId: action.id,
      deepLink: this.toPath(deepLink),
      actionType: action.type,
    });

    const results = await Promise.allSettled(
      subscriptions.map((sub) =>
        webpush
          .sendNotification(
            { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
            payload,
          )
          .catch((err: webpush.WebPushError) => {
            // 410 Gone or 404 means subscription expired — clean up
            if (err.statusCode === 410 || err.statusCode === 404) {
              this.repo.deleteByEndpointForAccount(action.accountId, sub.endpoint);
              this.log?.info(`Removed expired push subscription: ${sub.endpoint.slice(0, 60)}...`);
            }
            throw err;
          }),
      ),
    );

    const sent = results.filter((r) => r.status === "fulfilled").length;
    if (sent > 0) {
      this.log?.info(`Sent ${sent} push notification(s) for action ${action.id}`);
    }
  }

  /** Strip origin from deep link — the service worker opens relative to its own origin. */
  private toPath(deepLink: string): string {
    try {
      return new URL(deepLink).pathname;
    } catch {
      return deepLink;
    }
  }

  private buildBody(action: PendingAction): string {
    const source = action.context.source;
    if (action.type === "key-approve") {
      return `Approve "${action.keyLabel}" for ${source}`;
    }
    return `Sign with "${action.passkeyLabel ?? "passkey"}" for ${source}`;
  }
}
