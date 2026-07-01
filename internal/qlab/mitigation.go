package qlab

import "fmt"

// Mitigation Lab (Phase 4).
//
// This is a didactic model of the post-quantum hardening ladder, NOT a wallet
// and NOT a transaction engine. Each rung (A..F) represents a defensive posture;
// EvaluateSpend reports whether a hypothetical spend would be *acceptable* under
// that posture and why. There is no real money involved (see Non-Goals).

// MitigationMode is one rung of the hardening ladder (README "Mitigation Ladder").
type MitigationMode string

const (
	ModeA MitigationMode = "A" // exposed public key (baseline, most vulnerable)
	ModeB MitigationMode = "B" // hash-only address; pubkey revealed only on spend
	ModeC MitigationMode = "C" // no live UTXO after public-key exposure
	ModeD MitigationMode = "D" // migration window after exposure
	ModeE MitigationMode = "E" // hybrid ECC + hash-based signatures
	ModeF MitigationMode = "F" // post-quantum signatures (ML-DSA / SLH-DSA)
)

// mitigationMigrationWindow is the maximum tolerated age of an exposed public
// key under ModeD before the spend is refused. Didactic only.
const mitigationMigrationWindowDays = 30

// MitigationModeName returns the short human-readable name of a mode.
func MitigationModeName(mode MitigationMode) string {
	switch mode {
	case ModeA:
		return "exposed public key"
	case ModeB:
		return "hash-only address"
	case ModeC:
		return "no live UTXO after exposure"
	case ModeD:
		return "migration window after exposure"
	case ModeE:
		return "hybrid ECC + hash signatures"
	case ModeF:
		return "post-quantum signatures"
	}
	return "unknown"
}

// MitigationModeDesc returns a longer description of what a mode enforces.
func MitigationModeDesc(mode MitigationMode) string {
	switch mode {
	case ModeA:
		return "Baseline posture: public keys may be exposed and spent from. Most vulnerable to a future Shor-capable adversary."
	case ModeB:
		return "Addresses commit only to a hash of the public key; the key is revealed at spend time, shrinking the exposure window."
	case ModeC:
		return "Funds must not sit on a public key once it has been exposed: no live UTXO on an exposed key is accepted."
	case ModeD:
		return "An exposed key is tolerated only inside a short migration window; older exposures must have been swept."
	case ModeE:
		return "Signatures must be hybrid: an ECC signature plus a hash-based signature, so a break of ECC alone is insufficient."
	case ModeF:
		return "Signatures must be post-quantum (e.g. ML-DSA or SLH-DSA). The posture most resistant to a quantum adversary."
	}
	return "unknown mitigation mode"
}

// MitigationLadder returns the rungs in order, from most vulnerable to hardest.
func MitigationLadder() []MitigationMode {
	return []MitigationMode{ModeA, ModeB, ModeC, ModeD, ModeE, ModeF}
}

// SpendRequest describes a hypothetical spend for the lab. It is a stance check,
// not a transaction: the fields describe the situation around a key/UTXO.
type SpendRequest struct {
	PubkeyExposed    bool   `json:"pubkey_exposed"`
	AddressType      string `json:"address_type"` // "p2pkh" | "p2sh" | "p2wpkh" | "p2tr"
	HasLiveUTXO      bool   `json:"has_live_utxo"`
	SignatureScheme  string `json:"signature_scheme"`             // "ecdsa" | "hybrid" | "ml-dsa" | "slh-dsa"
	AgeAfterExposure string `json:"age_after_exposure,omitempty"` // e.g. "30d"; parsed loosely as days
}

// SpendDecision is the verdict of EvaluateSpend.
type SpendDecision struct {
	Mode    MitigationMode `json:"mode"`
	Allowed bool           `json:"allowed"`
	Reason  string         `json:"reason"`
}

// EvaluateSpend reports whether a hypothetical spend is acceptable under a given
// mitigation mode, and why. The rules are intentionally simple and educational.
func EvaluateSpend(mode MitigationMode, req SpendRequest) SpendDecision {
	switch mode {
	case ModeA:
		// Baseline: everything is allowed. This is the vulnerable starting point.
		return SpendDecision{Mode: mode, Allowed: true, Reason: "baseline mode: exposed public keys are accepted"}
	case ModeB:
		// Hash-only addresses: a raw p2pkh (which embeds the pubkey) is refused.
		if req.AddressType == "p2pkh" {
			return SpendDecision{Mode: mode, Allowed: false, Reason: "hash-only mode refuses p2pkh (pubkey embedded in address)"}
		}
		if !isHashAddress(req.AddressType) {
			return SpendDecision{Mode: mode, Allowed: false, Reason: fmt.Sprintf("hash-only mode requires a hash-based address, got %q", req.AddressType)}
		}
		return SpendDecision{Mode: mode, Allowed: true, Reason: "hash-based address; pubkey exposed only at spend time"}
	case ModeC:
		// No live UTXO on an exposed key.
		if req.PubkeyExposed && req.HasLiveUTXO {
			return SpendDecision{Mode: mode, Allowed: false, Reason: "live UTXO on an exposed public key is not allowed"}
		}
		return SpendDecision{Mode: mode, Allowed: true, Reason: "no live UTXO on an exposed key"}
	case ModeD:
		// Tolerate exposure only inside the migration window.
		if req.PubkeyExposed {
			days := parseDays(req.AgeAfterExposure)
			if days > mitigationMigrationWindowDays {
				return SpendDecision{Mode: mode, Allowed: false, Reason: fmt.Sprintf("exposure is %d days old, exceeds the %d-day migration window", days, mitigationMigrationWindowDays)}
			}
			return SpendDecision{Mode: mode, Allowed: true, Reason: fmt.Sprintf("exposure within the %d-day migration window", mitigationMigrationWindowDays)}
		}
		return SpendDecision{Mode: mode, Allowed: true, Reason: "no exposure; no window constraint"}
	case ModeE:
		// Require hybrid (or stronger) signatures. ecdsa alone is refused.
		if req.SignatureScheme == "ecdsa" || req.SignatureScheme == "" {
			return SpendDecision{Mode: mode, Allowed: false, Reason: "hybrid mode refuses ECC-only signatures"}
		}
		if req.SignatureScheme != "hybrid" {
			return SpendDecision{Mode: mode, Allowed: false, Reason: fmt.Sprintf("hybrid mode expects a hybrid signature, got %q", req.SignatureScheme)}
		}
		return SpendDecision{Mode: mode, Allowed: true, Reason: "hybrid ECC + hash-based signature accepted"}
	case ModeF:
		// Require post-quantum signatures.
		if req.SignatureScheme != "ml-dsa" && req.SignatureScheme != "slh-dsa" {
			return SpendDecision{Mode: mode, Allowed: false, Reason: fmt.Sprintf("post-quantum mode requires ml-dsa or slh-dsa, got %q", req.SignatureScheme)}
		}
		return SpendDecision{Mode: mode, Allowed: true, Reason: fmt.Sprintf("post-quantum signature (%s) accepted", req.SignatureScheme)}
	}
	return SpendDecision{Mode: mode, Allowed: false, Reason: fmt.Sprintf("unknown mitigation mode %q", mode)}
}

// isHashAddress reports whether an address type commits to a hash of the key
// rather than embedding the key directly.
func isHashAddress(addressType string) bool {
	switch addressType {
	case "p2sh", "p2wpkh", "p2wsh", "p2tr":
		return true
	}
	return false
}

// parseDays reads an age like "30d" or "12d" as a number of days. Unknown or
// malformed values are treated as 0 days (the most lenient reading), so the
// caller still gets a well-defined decision.
func parseDays(age string) int {
	if len(age) < 2 || age[len(age)-1] != 'd' {
		return 0
	}
	n := 0
	for _, r := range age[:len(age)-1] {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
