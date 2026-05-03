// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
import type { PendingAction } from "./types.js";

export interface NotificationChannel {
  readonly name: string;
  send(action: PendingAction, deepLink: string): Promise<void>;
}

export class NotificationDispatcher {
  private channels: NotificationChannel[] = [];
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  register(channel: NotificationChannel): void {
    this.channels.push(channel);
  }

  async dispatch(action: PendingAction): Promise<void> {
    const deepLink = `${this.baseUrl}/sign/${action.id}`;
    await Promise.allSettled(this.channels.map((ch) => ch.send(action, deepLink)));
  }
}
