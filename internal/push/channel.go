// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// Package push is the Web Push notification channel (port of
// src/pending-action/push-channel.ts): approval prompts reach subscribed
// browsers even without an open tab. Registered on the broker only when VAPID
// is configured. Expired subscriptions (404/410 from the push service) are
// pruned on delivery.
package push

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/rado0x54/shellwatch/internal/approval"
	"github.com/rado0x54/shellwatch/internal/store"
)

// Vapid carries the configured VAPID identity.
type Vapid struct {
	Subject    string
	PublicKey  string
	PrivateKey string
}

// Channel implements approval.Channel over Web Push.
type Channel struct {
	Subs  *store.PushSubs
	Vapid Vapid
	// send is swappable in tests; defaults to webpush.SendNotificationWithContext.
	send func(ctx context.Context, message []byte, s *webpush.Subscription, o *webpush.Options) (int, error)
}

// NewChannel builds the channel.
func NewChannel(subs *store.PushSubs, vapid Vapid) *Channel {
	return &Channel{Subs: subs, Vapid: vapid, send: defaultSend}
}

func defaultSend(ctx context.Context, message []byte, s *webpush.Subscription, o *webpush.Options) (int, error) {
	res, err := webpush.SendNotificationWithContext(ctx, message, s, o)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	return res.StatusCode, nil
}

var _ approval.Channel = (*Channel)(nil)

// payload matches the Node service worker's expectations (push-channel.ts).
type payload struct {
	Title      string `json:"title"`
	Body       string `json:"body"`
	ActionID   string `json:"actionId"`
	DeepLink   string `json:"deepLink"`
	ActionType string `json:"actionType"`
}

// Notify delivers the action to every subscription of the owning account.
// Fire-and-forget: the broker must not block on push-service round-trips.
func (c *Channel) Notify(action *approval.Action, deepLink string) {
	go c.deliver(action, deepLink)
}

// Resolved is a no-op (Node's PushChannel doesn't notify resolution).
func (c *Channel) Resolved(*approval.Action) {}

func (c *Channel) deliver(action *approval.Action, deepLink string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	subs, err := c.Subs.ListForAccount(ctx, action.AccountID)
	if err != nil || len(subs) == 0 {
		return
	}
	title := "SSH Key Approval Requested"
	body := `Approve "` + action.KeyLabel + `" for ` + action.Context.Source
	if action.Type == approval.TypeWebAuthnSign {
		title = "Passkey Signature Requested"
		label := action.PasskeyLabel
		if label == "" {
			label = "passkey"
		}
		body = `Sign with "` + label + `" for ` + action.Context.Source
	}
	raw, err := json.Marshal(payload{
		Title: title, Body: body, ActionID: action.ID,
		DeepLink: toPath(deepLink), ActionType: string(action.Type),
	})
	if err != nil {
		return
	}

	sent := 0
	for _, sub := range subs {
		status, err := c.send(ctx, raw, &webpush.Subscription{
			Endpoint: sub.Endpoint,
			Keys:     webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
		}, &webpush.Options{
			Subscriber:      c.Vapid.Subject,
			VAPIDPublicKey:  c.Vapid.PublicKey,
			VAPIDPrivateKey: c.Vapid.PrivateKey,
			TTL:             60,
		})
		if err != nil {
			slog.Warn("web-push send failed", "action", action.ID, "err", err)
			continue
		}
		// 410 Gone / 404: the subscription expired — clean it up.
		if status == 404 || status == 410 {
			_ = c.Subs.Delete(ctx, action.AccountID, sub.Endpoint)
			slog.Info("removed expired push subscription", "endpoint", truncate(sub.Endpoint, 60))
			continue
		}
		if status >= 200 && status < 300 {
			sent++
		}
	}
	if sent > 0 {
		slog.Info("sent push notifications", "action", action.ID, "count", sent)
	}
}

// toPath strips the origin — the service worker opens relative to its own.
func toPath(deepLink string) string {
	if u, err := url.Parse(deepLink); err == nil && u.Path != "" {
		return u.Path
	}
	return deepLink
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
