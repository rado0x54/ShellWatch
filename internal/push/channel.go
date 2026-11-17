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
	"io"
	"log/slog"
	"net/url"
	"strings"
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
	// It returns the HTTP status and, for non-2xx, the push service's reason.
	send func(ctx context.Context, message []byte, s *webpush.Subscription, o *webpush.Options) (int, string, error)
}

// NewChannel builds the channel.
func NewChannel(subs *store.PushSubs, vapid Vapid) *Channel {
	vapid.Subject = subscriberForLib(vapid.Subject)
	return &Channel{Subs: subs, Vapid: vapid, send: defaultSend}
}

// subscriberForLib adapts the configured VAPID subject to webpush-go, which
// prepends "mailto:" to anything not starting with "https:". The config
// documents the RFC 8292 form ("mailto:admin@example.com"); passed through
// as-is it becomes "mailto:mailto:…", which Apple's push service rejects
// with 403 BadJwtToken (FCM and Mozilla tolerate it).
func subscriberForLib(subject string) string {
	return strings.TrimPrefix(subject, "mailto:")
}

// maxReasonBytes bounds how much of a refusal body is read and logged.
const maxReasonBytes = 256

func defaultSend(ctx context.Context, message []byte, s *webpush.Subscription, o *webpush.Options) (int, string, error) {
	res, err := webpush.SendNotificationWithContext(ctx, message, s, o)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return res.StatusCode, "", nil
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxReasonBytes))
	return res.StatusCode, refusalReason(body), nil
}

// refusalReason condenses a push service's error body for the log: Apple
// answers {"reason":"BadJwtToken"}, FCM and Mozilla a short text or JSON.
// The body names the failure only; it carries no subscription secrets.
func refusalReason(body []byte) string {
	var apple struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(body, &apple) == nil && apple.Reason != "" {
		return apple.Reason
	}
	return strings.Join(strings.Fields(string(body)), " ")
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

// HostKeyMismatch is the push payload input for a host-key mismatch (#241).
type HostKeyMismatch struct {
	AccountID           string
	EndpointLabel       string
	EndpointAddress     string
	ObservedFingerprint string
	PinnedFingerprint   string
}

// NotifyHostKeyMismatch pushes a high-priority host-key-mismatch alert: the
// connection died before authentication, so no approval toast exists — this
// (plus the WS message) is how the human learns a possible MITM was blocked.
// Fire-and-forget like Notify.
func (c *Channel) NotifyHostKeyMismatch(m HostKeyMismatch) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		raw, err := json.Marshal(payload{
			Title: "SSH host key MISMATCH blocked",
			Body: `"` + m.EndpointLabel + `" (` + m.EndpointAddress + `) presented ` + m.ObservedFingerprint +
				` but ` + m.PinnedFingerprint + ` is pinned. The connection was refused. Review it in Settings -> Endpoints.`,
			DeepLink:   "/settings/endpoints",
			ActionType: "host-key-mismatch",
		})
		if err != nil {
			return
		}
		c.sendToAccount(ctx, m.AccountID, raw, "host-key-mismatch")
	}()
}

// UnauthenticatedEndpoint is the push payload input for a connection refused
// because the server accepted SSH "none" authentication (#311).
type UnauthenticatedEndpoint struct {
	AccountID       string
	EndpointLabel   string
	EndpointAddress string
	RemoteUser      string
}

// NotifyUnauthenticatedEndpoint pushes the none-auth refusal alert. There is
// no action to resolve, so the push carries no actionId and no /sign/:id
// link: it opens the Notifications tab. Fire-and-forget like Notify.
func (c *Channel) NotifyUnauthenticatedEndpoint(m UnauthenticatedEndpoint) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		raw, err := json.Marshal(payload{
			Title: "Connection refused: no authentication",
			Body: `"` + m.EndpointLabel + `" (` + m.EndpointAddress + `) accepted SSH access as ` + m.RemoteUser +
				` without a key. ShellWatch does not open sessions on such servers. Check the server's SSH configuration.`,
			DeepLink:   "/audit/notifications",
			ActionType: "unauthenticated-endpoint",
		})
		if err != nil {
			return
		}
		c.sendToAccount(ctx, m.AccountID, raw, "unauthenticated-endpoint")
	}()
}

func (c *Channel) deliver(action *approval.Action, deepLink string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
	if action.Context.TriggerKind == "ticket" {
		// A one-time access guest (#306). The code and the reason stay off
		// the push service; the notification opens /sign, which shows them.
		title = "Guest Access Requested"
		body = "A one-time access guest is waiting — open to compare the confirmation code"
	}
	if hk := action.Context.HostKey; hk != nil && hk.Status == "new" {
		body += ` — FIRST connection to this host: approving pins host key ` + hk.Fingerprint
	}
	raw, err := json.Marshal(payload{
		Title: title, Body: body, ActionID: action.ID,
		DeepLink: toPath(deepLink), ActionType: string(action.Type),
	})
	if err != nil {
		return
	}
	c.sendToAccount(ctx, action.AccountID, raw, action.ID)
}

// sendToAccount delivers one payload to every subscription of an account,
// pruning expired subscriptions. logRef names the trigger in logs.
func (c *Channel) sendToAccount(ctx context.Context, accountID string, raw []byte, logRef string) {
	subs, err := c.Subs.ListForAccount(ctx, accountID)
	if err != nil || len(subs) == 0 {
		return
	}
	sent := 0
	for _, sub := range subs {
		status, reason, err := c.send(ctx, raw, &webpush.Subscription{
			Endpoint: sub.Endpoint,
			Keys:     webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
		}, &webpush.Options{
			Subscriber:      c.Vapid.Subject,
			VAPIDPublicKey:  c.Vapid.PublicKey,
			VAPIDPrivateKey: c.Vapid.PrivateKey,
			TTL:             60,
		})
		if err != nil {
			slog.Warn("push: send failed", "ref", logRef, "pushHost", endpointHost(sub.Endpoint), "err", err)
			continue
		}
		// 410 Gone / 404: the subscription expired — clean it up.
		if status == 404 || status == 410 {
			_ = c.Subs.Delete(ctx, accountID, sub.Endpoint)
			slog.Info("push: removed expired subscription", "account", accountID, "pushHost", endpointHost(sub.Endpoint), "status", status, "reason", reason)
			continue
		}
		if status >= 200 && status < 300 {
			sent++
			continue
		}
		// Anything else (403 VAPID mismatch, 413, 429 …) drops the
		// notification for this device; the subscription stays.
		slog.Warn("push: push service refused the notification", "ref", logRef, "pushHost", endpointHost(sub.Endpoint), "status", status, "reason", reason)
	}
	slog.Info("push: notifications sent", "ref", logRef, "account", accountID, "sent", sent, "subscriptions", len(subs))
}

// toPath strips the origin — the service worker opens relative to its own.
func toPath(deepLink string) string {
	if u, err := url.Parse(deepLink); err == nil && u.Path != "" {
		return u.Path
	}
	return deepLink
}

// endpointHost is the push service host (fcm.googleapis.com,
// web.push.apple.com …): the full endpoint URL is a capability.
func endpointHost(endpoint string) string {
	if u, err := url.Parse(endpoint); err == nil {
		return u.Host
	}
	return ""
}
