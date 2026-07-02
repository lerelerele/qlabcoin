package qlab

import (
	"bytes"
	"testing"
)

// Test helpers for signed-identity (v2). Tests that build attributed events
// (submit, reproduce) must sign them; these helpers provide a fixed key pair and
// a signer so tests stay readable.

// testAuthorKey is a deterministic ed25519 key pair used across tests. Generated
// once at init time; deterministic enough for test assertions that do not pin
// the exact signature bytes (none do).
var testAuthorKey = mustGenerateTestKey()

func mustGenerateTestKey() struct{ pub, priv []byte } {
	pub, priv, err := GenerateIdentity()
	if err != nil {
		panic(err)
	}
	return struct{ pub, priv []byte }{pub, priv}
}

// signTestEvent sets ev.Author to the test author and attaches a valid ed25519
// signature over the canonical payload, returning the signed event. The author's
// public key is available via testAuthorKey.pub for a preceding register event.
func signTestEvent(tb testing.TB, ev Event) Event {
	tb.Helper()
	ev.Author = "test-author"
	sig, err := SignEvent(testAuthorKey.priv, ev)
	if err != nil {
		tb.Fatalf("SignEvent: %v", err)
	}
	ev.Signature = sig
	return ev
}

// appendTestRegister prepends an EventRegister for the test author so subsequent
// signed events replay as registered. Call once before the first attributed event.
func appendTestRegister(tb testing.TB, c *Chain) {
	tb.Helper()
	ev := Event{
		Type:      EventRegister,
		Level:     0,
		Author:    "test-author",
		Identity:  &Identity{Author: "test-author", PubKey: testAuthorKey.pub},
		Timestamp: "2026-01-01T00:00:00Z",
	}
	if _, err := c.Append(ev); err != nil {
		tb.Fatalf("append register: %v", err)
	}
}

// --- Unit tests for the identity primitives themselves ---

func TestGenerateIdentityProducesValidKeyPair(t *testing.T) {
	pub, priv, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if !ValidPublicKey(pub) {
		t.Fatalf("public key invalid: %d bytes", len(pub))
	}
	if len(priv) != 64 {
		t.Fatalf("private key = %d bytes, want 64", len(priv))
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ev := Event{Type: EventSubmit, Level: 5, Author: "a", Timestamp: "t",
		Submission: &Submission{Solution: "36", CircuitHash: "sha256:x"}}
	sig, err := SignEvent(testAuthorKey.priv, ev)
	if err != nil {
		t.Fatalf("SignEvent: %v", err)
	}
	if err := VerifyEventSignature(testAuthorKey.pub, ev, sig); err != nil {
		t.Fatalf("VerifyEventSignature: %v", err)
	}
}

// TestTamperedPayloadFails: changing the event after signing must break the
// signature. This is the core tamper-evidence guarantee.
func TestTamperedPayloadFails(t *testing.T) {
	ev := Event{Type: EventSubmit, Level: 5, Author: "a", Timestamp: "t",
		Submission: &Submission{Solution: "36", CircuitHash: "sha256:x"}}
	sig, _ := SignEvent(testAuthorKey.priv, ev)
	ev.Level = 6 // tamper
	if err := VerifyEventSignature(testAuthorKey.pub, ev, sig); err == nil {
		t.Fatal("signature verified after tampering the payload")
	}
}

func TestSigningBytesDeterministic(t *testing.T) {
	ev := Event{Type: EventSubmit, Level: 5, Author: "a", Timestamp: "t",
		Submission: &Submission{Solution: "36", CircuitHash: "sha256:x"}}
	a := SigningBytes(ev)
	b := SigningBytes(ev)
	if !bytes.Equal(a, b) {
		t.Fatal("SigningBytes not deterministic for the same event")
	}
	// A different submission must yield different bytes.
	ev2 := ev
	ev2.Submission = &Submission{Solution: "37", CircuitHash: "sha256:x"}
	if bytes.Equal(a, SigningBytes(ev2)) {
		t.Fatal("SigningBytes identical for different payloads")
	}
}

// TestSignatureExcludedFromSigningBytes: mutating only the signature field must
// not change SigningBytes (a signature cannot sign itself).
func TestSignatureExcludedFromSigningBytes(t *testing.T) {
	ev := Event{Type: EventSubmit, Level: 5, Author: "a", Timestamp: "t"}
	before := SigningBytes(ev)
	ev.Signature = []byte{1, 2, 3, 4}
	after := SigningBytes(ev)
	if !bytes.Equal(before, after) {
		t.Fatal("SigningBytes changed when only the signature field was set")
	}
}

func TestVerifyEventSignatureRejectsBadKeyOrSig(t *testing.T) {
	ev := Event{Type: EventSubmit, Level: 5, Author: "a", Timestamp: "t"}
	sig, _ := SignEvent(testAuthorKey.priv, ev)
	// Wrong key size.
	if err := VerifyEventSignature([]byte{1, 2, 3}, ev, sig); err == nil {
		t.Fatal("accepted malformed public key")
	}
	// Wrong signature size.
	if err := VerifyEventSignature(testAuthorKey.pub, ev, []byte{1, 2, 3}); err == nil {
		t.Fatal("accepted malformed signature")
	}
}
