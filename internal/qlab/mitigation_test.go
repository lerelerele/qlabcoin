package qlab

import "testing"

func TestMitigationLadderComplete(t *testing.T) {
	got := MitigationLadder()
	want := []MitigationMode{ModeA, ModeB, ModeC, ModeD, ModeE, ModeF}
	if len(got) != len(want) {
		t.Fatalf("ladder length = %d, want %d", len(got), len(want))
	}
	for i, m := range got {
		if m != want[i] {
			t.Fatalf("ladder[%d] = %q, want %q", i, m, want[i])
		}
		if MitigationModeName(m) == "unknown" {
			t.Fatalf("mode %q has no name", m)
		}
		if MitigationModeDesc(m) == "unknown mitigation mode" {
			t.Fatalf("mode %q has no description", m)
		}
	}
}

// TestEvaluateSpendPerMode: one accept and one reject per rung A-F.
func TestEvaluateSpendPerMode(t *testing.T) {
	cases := []struct {
		name   string
		mode   MitigationMode
		req    SpendRequest
		accept bool
	}{
		// A: baseline allows everything; reject case is not applicable (A never rejects),
		// so we assert A always allows and exercise a "deny" only on B-F.
		{"A allows exposed", ModeA, SpendRequest{PubkeyExposed: true, AddressType: "p2pkh", SignatureScheme: "ecdsa"}, true},

		{"B rejects p2pkh", ModeB, SpendRequest{AddressType: "p2pkh"}, false},
		{"B accepts p2wpkh", ModeB, SpendRequest{AddressType: "p2wpkh"}, true},

		{"C rejects live utxo on exposed key", ModeC, SpendRequest{PubkeyExposed: true, HasLiveUTXO: true}, false},
		{"C accepts no live utxo", ModeC, SpendRequest{PubkeyExposed: true, HasLiveUTXO: false}, true},

		{"D rejects old exposure", ModeD, SpendRequest{PubkeyExposed: true, AgeAfterExposure: "60d"}, false},
		{"D accepts fresh exposure", ModeD, SpendRequest{PubkeyExposed: true, AgeAfterExposure: "10d"}, true},

		{"E rejects ecdsa", ModeE, SpendRequest{SignatureScheme: "ecdsa"}, false},
		{"E accepts hybrid", ModeE, SpendRequest{SignatureScheme: "hybrid"}, true},

		{"F rejects hybrid (not pq)", ModeF, SpendRequest{SignatureScheme: "hybrid"}, false},
		{"F accepts ml-dsa", ModeF, SpendRequest{SignatureScheme: "ml-dsa"}, true},
	}
	for _, c := range cases {
		d := EvaluateSpend(c.mode, c.req)
		if d.Allowed != c.accept {
			t.Fatalf("%s: allowed=%v want %v (reason %q)", c.name, d.Allowed, c.accept, d.Reason)
		}
	}
}

// TestEvaluateSpendModeAAlwaysAllows: the baseline never refuses, even for the
// most exposed request.
func TestEvaluateSpendModeAAlwaysAllows(t *testing.T) {
	d := EvaluateSpend(ModeA, SpendRequest{PubkeyExposed: true, HasLiveUTXO: true, AddressType: "p2pkh", SignatureScheme: "ecdsa"})
	if !d.Allowed {
		t.Fatalf("ModeA rejected a spend (reason %q); baseline must allow everything", d.Reason)
	}
}

func TestParseDays(t *testing.T) {
	cases := map[string]int{"0d": 0, "5d": 5, "30d": 30, "100d": 100, "": 0, "abc": 0, "12": 0}
	for in, want := range cases {
		if got := parseDays(in); got != want {
			t.Fatalf("parseDays(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestDeriveMitigationModeByBand: the derived mode climbs the ladder as more /
// higher levels are broken.
func TestDeriveMitigationModeByBand(t *testing.T) {
	cases := []struct {
		maxBroken int
		want      MitigationMode
	}{
		{0, ModeA}, // nothing broken
		{1, ModeB}, // first break (band B)
		{4, ModeB}, // still band B
		{5, ModeC}, // band C
		{18, ModeC},
		{FirstECDLPLevel, ModeD}, // 19, first ECDLP-shaped
		{99, ModeD},
		{100, ModeE}, // band E
		{999, ModeE},
		{1000, ModeF}, // band F
		{BitcoinLogicalThreshold, ModeF},
	}
	for _, c := range cases {
		r := NewRegistry("")
		if c.maxBroken > 0 {
			e, _ := r.Entry(c.maxBroken)
			e.State = StateBroken
		}
		got := DeriveMitigationMode(r)
		if got != c.want {
			t.Fatalf("maxBroken=%d: mode=%s want %s", c.maxBroken, got, c.want)
		}
	}
}

// TestMaxBrokenLevelSkipsOpenLevels: only broken/hardened/reopened count.
func TestMaxBrokenLevelSkipsOpenLevels(t *testing.T) {
	r := NewRegistry("")
	e3, _ := r.Entry(3)
	e3.State = StateOpen
	e5, _ := r.Entry(5)
	e5.State = StateBroken
	e2, _ := r.Entry(2)
	e2.State = StateHardened
	if got := r.MaxBrokenLevel(); got != 5 {
		t.Fatalf("MaxBrokenLevel = %d, want 5", got)
	}
}

// TestDeriveMitigationModeFromRealChain: end-to-end, breaking a level on the
// chain raises the derived mode.
func TestDeriveMitigationModeFromRealChain(t *testing.T) {
	c := newTestChain(t)
	// Empty chain -> ModeA.
	r, _ := DeriveRegistry(c)
	if got := DeriveMitigationMode(r); got != ModeA {
		t.Fatalf("empty chain mode = %s, want A", got)
	}
	// Break level 5 -> ModeC (band 5).
	sub := Submission{Solution: "36", CircuitHash: "sha256:abc", VerifiedAt: "t"}
	c.Append(Event{Type: EventSubmit, Level: 5, Submission: &sub, Timestamp: "t"})
	r2, err := DeriveRegistry(c)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got := DeriveMitigationMode(r2); got != ModeC {
		t.Fatalf("after level 5 broken, mode = %s, want C", got)
	}
}
