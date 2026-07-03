// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
// WSChannel delivers sign:request / sign:resolved to the account's browser
// sockets via the hub's narrow SendToAccount seam (port of ws-channel.ts).
// This replaces the Node WebSocketChannel that reached into the WS handler's
// lifecycle — the hub owns sockets, the channel just sends (W3/W5 fix).
package approval

// AccountSender is the hub seam (implemented by ws.Hub.SendToAccount).
type AccountSender interface {
	SendToAccount(accountID string, msg any)
}

// WSChannel is a notification Channel backed by the WS hub.
type WSChannel struct {
	Hub AccountSender
}

// Notify sends a sign:request toast with a deep link. The payload carries every
// field the browser toast renders (port of ws-channel.ts) — notably actionType
// (which selects the webauthn-sign vs key-approve render branch) and the
// per-type detail fields. Omitting them made the SPA read credentialId off a
// key-approve action and crash.
func (c *WSChannel) Notify(a *Action, deepLink string) {
	payload := map[string]any{
		"type":       "sign:request",
		"actionId":   a.ID,
		"actionType": string(a.Type),
		"deepLink":   deepLink,
		"source":     a.Context.Source,
	}
	if a.Context.EndpointLabel != "" {
		payload["endpointLabel"] = a.Context.EndpointLabel
	}
	if a.Context.EndpointAddress != "" {
		payload["endpointAddress"] = a.Context.EndpointAddress
	}
	switch a.Type {
	case TypeWebAuthnSign:
		payload["passkeyLabel"] = a.PasskeyLabel
		payload["credentialId"] = a.CredentialID
		payload["challenge"] = a.Challenge
		payload["rpId"] = a.RpID
	case TypeKeyApprove:
		payload["keyLabel"] = a.KeyLabel
		payload["keyFingerprint"] = a.KeyFingerprint
	}
	c.Hub.SendToAccount(a.AccountID, payload)
}

// Resolved clears the toast on other tabs.
func (c *WSChannel) Resolved(a *Action) {
	c.Hub.SendToAccount(a.AccountID, map[string]any{
		"type":     "sign:resolved",
		"actionId": a.ID,
	})
}

var _ Channel = (*WSChannel)(nil)
