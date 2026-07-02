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

// Notify sends a sign:request toast with a deep link.
func (c *WSChannel) Notify(a *Action, deepLink string) {
	c.Hub.SendToAccount(a.AccountID, map[string]any{
		"type":     "sign:request",
		"actionId": a.ID,
		"redirect": deepLink,
	})
}

// Resolved clears the toast on other tabs.
func (c *WSChannel) Resolved(a *Action) {
	c.Hub.SendToAccount(a.AccountID, map[string]any{
		"type":     "sign:resolved",
		"actionId": a.ID,
	})
}

var _ Channel = (*WSChannel)(nil)
