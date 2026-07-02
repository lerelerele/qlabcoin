package qlab

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// Signed identity (v2). Authors register an ed25519 public key on the chain;
// every attributed event (submit, reproduce) carries an ed25519 signature over a
// canonical payload that the replay verifies against the registered key. This is
// attribution, not a PKI: "who the author is in the real world" is a social/PR
// concern; the chain only guarantees that an event signed under a key was indeed
// produced by the holder of that key.

// Ed25519PublicKeySize and Ed25519SignatureSize re-export the stdlib sizes so
// callers (and tests) do not need to import crypto/ed25519 to validate lengths.
const (
	ed25519PubSize = ed25519.PublicKeySize // 32
	ed25519SigSize = ed25519.SignatureSize // 64
)

// Identity binds an author handle to an ed25519 public key. It is published by an
// EventRegister and used to verify signatures on subsequent attributed events.
type Identity struct {
	Author string `json:"author"`
	PubKey []byte `json:"pubkey"`
}

// GenerateIdentity creates a new ed25519 key pair. The public key is meant to be
// registered on chain; the private key is kept offline by the author.
func GenerateIdentity() (pub, priv []byte, err error) {
	return ed25519.GenerateKey(nil)
}

// signableEvent is the canonical shape of an event for signing/verifying. It
// excludes the Signature field itself (which cannot sign itself) and the PubKey
// (which is carried by the Event for self-containment but is established via the
// register flow). Field order is fixed for determinism.
type signableEvent struct {
	Type         EventType     `json:"type"`
	Level        int           `json:"level"`
	Author       string        `json:"author"`
	Submission   *Submission   `json:"submission,omitempty"`
	Reproduction *Reproduction `json:"reproduction,omitempty"`
	Identity     *Identity     `json:"identity,omitempty"`
	Timestamp    string        `json:"timestamp"`
}

// SigningBytes returns the deterministic payload that an event signature covers.
// It is sha256 over the canonical JSON of the event minus its signature, so two
// holders of the same event material compute the same bytes.
func SigningBytes(ev Event) []byte {
	s := signableEvent{
		Type:         ev.Type,
		Level:        ev.Level,
		Author:       ev.Author,
		Submission:   ev.Submission,
		Reproduction: ev.Reproduction,
		Identity:     ev.Identity,
		Timestamp:    ev.Timestamp,
	}
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return h[:]
}

// SignEvent signs the canonical payload of ev with the given ed25519 private key.
// priv must be a 64-byte ed25519 private key (seed + pubkey). The returned
// signature is 64 bytes.
func SignEvent(priv []byte, ev Event) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ed25519 private key: %d bytes (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(ed25519.PrivateKey(priv), SigningBytes(ev)), nil
}

// VerifyEventSignature checks that sig is a valid ed25519 signature over the
// canonical payload of ev, under pub. It does NOT check whether pub is
// registered; that is the replay's job (see derivation.go).
func VerifyEventSignature(pub []byte, ev Event, sig []byte) error {
	if len(pub) != ed25519PubSize {
		return fmt.Errorf("invalid public key: %d bytes (want %d)", len(pub), ed25519PubSize)
	}
	if len(sig) != ed25519SigSize {
		return fmt.Errorf("invalid signature: %d bytes (want %d)", len(sig), ed25519SigSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), SigningBytes(ev), sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// ValidPublicKey reports whether pub is a well-formed ed25519 public key.
func ValidPublicKey(pub []byte) bool {
	return len(pub) == ed25519PubSize
}
