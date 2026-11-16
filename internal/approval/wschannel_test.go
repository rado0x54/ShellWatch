// SPDX-License-Identifier: LicenseRef-FSL-1.1-Apache-2.0
package approval

import "testing"

type capturingSender struct{ last map[string]any }

func (c *capturingSender) SendToAccount(_ string, msg any) { c.last = msg.(map[string]any) }

func TestWSChannelNotifyWebAuthnSign(t *testing.T) {
	cap := &capturingSender{}
	ch := &WSChannel{Hub: cap}
	ch.Notify(&Action{
		ID: "act1", AccountID: "acc", Type: TypeWebAuthnSign,
		Context:      Context{Source: "agent-proxy", EndpointLabel: "Prod", EndpointAddress: "u@h:22"},
		CredentialID: "cred-1", Challenge: "dGVzdA==", RpID: "localhost", PasskeyLabel: "YubiKey",
	}, "https://x/sign/act1")

	m := cap.last
	// The SPA renders these unconditionally for webauthn-sign — all must be set,
	// and actionType must select the right branch (the crash was a missing one).
	want := map[string]any{
		"type": "sign:request", "actionId": "act1", "actionType": "webauthn-sign",
		"deepLink": "https://x/sign/act1", "source": "agent-proxy",
		"endpointLabel": "Prod", "endpointAddress": "u@h:22",
		"passkeyLabel": "YubiKey", "credentialId": "cred-1", "challenge": "dGVzdA==", "rpId": "localhost",
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("field %q = %v, want %v", k, m[k], v)
		}
	}
	if _, ok := m["keyLabel"]; ok {
		t.Error("webauthn-sign payload must not carry keyLabel")
	}
}

func TestWSChannelNotifyKeyApprove(t *testing.T) {
	cap := &capturingSender{}
	(&WSChannel{Hub: cap}).Notify(&Action{
		ID: "act2", AccountID: "acc", Type: TypeKeyApprove,
		Context:  Context{Source: "endpoint-auth", EndpointLabel: "Prod"},
		KeyLabel: "Deploy Key", KeyFingerprint: "SHA256:abc",
	}, "https://x/sign/act2")

	m := cap.last
	if m["actionType"] != "key-approve" || m["keyLabel"] != "Deploy Key" || m["keyFingerprint"] != "SHA256:abc" {
		t.Errorf("key-approve payload wrong: %v", m)
	}
	if _, ok := m["credentialId"]; ok {
		t.Error("key-approve payload must not carry credentialId (SPA reads it only for webauthn-sign)")
	}
}

// A ticket guest's prompt (#306) carries the guest context so the toast can
// show the confirmation code; ordinary prompts carry no ticket key.
func TestWSChannelNotifyTicket(t *testing.T) {
	cap := &capturingSender{}
	ch := &WSChannel{Hub: cap}
	ch.Notify(&Action{
		ID: "act3", AccountID: "acc", Type: TypeKeyApprove, KeyLabel: "k",
		Context: Context{Source: "endpoint-auth", TriggerKind: "ticket", SourceIP: "203.0.113.7",
			MCPReason: "fix the printer",
			Ticket:    &TicketContext{TicketID: "tk1", Label: "Printer", ConfirmationCode: "AB2C"}},
	}, "https://x/sign/act3")
	tk, ok := cap.last["ticket"].(map[string]any)
	if !ok {
		t.Fatalf("no ticket in %v", cap.last)
	}
	for k, v := range map[string]any{"ticketId": "tk1", "ticketLabel": "Printer", "confirmationCode": "AB2C",
		"reason": "fix the printer", "sourceIp": "203.0.113.7"} {
		if tk[k] != v {
			t.Errorf("ticket.%s = %v, want %v", k, tk[k], v)
		}
	}
	ch.Notify(&Action{ID: "act4", AccountID: "acc", Type: TypeKeyApprove,
		Context: Context{Source: "endpoint-auth", TriggerKind: "ui"}}, "https://x/sign/act4")
	if _, ok := cap.last["ticket"]; ok {
		t.Error("non-ticket prompt carries ticket")
	}
}
