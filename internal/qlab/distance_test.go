package qlab

import (
	"math"
	"testing"
)

func profileByName(t *testing.T, name string) QECProfile {
	t.Helper()
	for _, p := range QECProfiles() {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("profile %q not found", name)
	return QECProfile{}
}

// TestDistanceOptimistic pins the numbers from the design notes: overhead 25
// gives 244 logical qubits per Q6100 (a ~24-bit reference curve) and puts the
// Bitcoin threshold at 10 processors.
func TestDistanceOptimistic(t *testing.T) {
	d := DistanceUnderProfile(profileByName(t, "optimistic"), 5)
	if d.LogicalPerProcessor != 244 {
		t.Fatalf("logical/Q6100 = %d, want 244", d.LogicalPerProcessor)
	}
	if d.MaxCurveBitsPerProcessor != 24 {
		t.Fatalf("curve bits/Q6100 = %d, want 24", d.MaxCurveBitsPerProcessor)
	}
	if d.ProcessorsForBitcoin != 10 {
		t.Fatalf("processors for Bitcoin = %d, want 10", d.ProcessorsForBitcoin)
	}
	if d.PhysicalQubitsForBitcoin != 2330*25 {
		t.Fatalf("physical for Bitcoin = %d, want %d", d.PhysicalQubitsForBitcoin, 2330*25)
	}
}

// TestDistanceModerate: overhead 100 gives 61 logical per Q6100 and 39
// processors for the threshold (the "nivel 39" figure from the notes).
func TestDistanceModerate(t *testing.T) {
	d := DistanceUnderProfile(profileByName(t, "moderate"), 5)
	if d.LogicalPerProcessor != 61 {
		t.Fatalf("logical/Q6100 = %d, want 61", d.LogicalPerProcessor)
	}
	if d.ProcessorsForBitcoin != 39 {
		t.Fatalf("processors for Bitcoin = %d, want 39", d.ProcessorsForBitcoin)
	}
}

// TestDistanceConservative: overhead 1000 leaves 6 logical qubits per Q6100 —
// not even a 1-bit reference curve fits — and 389 processors for the threshold.
func TestDistanceConservative(t *testing.T) {
	d := DistanceUnderProfile(profileByName(t, "conservative"), 5)
	if d.LogicalPerProcessor != 6 {
		t.Fatalf("logical/Q6100 = %d, want 6", d.LogicalPerProcessor)
	}
	if d.MaxCurveBitsPerProcessor != 0 {
		t.Fatalf("curve bits/Q6100 = %d, want 0 (cannot fit a 1-bit curve)", d.MaxCurveBitsPerProcessor)
	}
	if d.ProcessorsForBitcoin != 389 {
		t.Fatalf("processors for Bitcoin = %d, want 389", d.ProcessorsForBitcoin)
	}
	if d.PhysicalQubitsForBitcoin != 2330000 {
		t.Fatalf("physical for Bitcoin = %d, want 2330000", d.PhysicalQubitsForBitcoin)
	}
}

// TestDistanceEmpirical: the empirical profile refuses hardware conversion —
// every hardware field stays zero and only the demonstrated clock remains.
func TestDistanceEmpirical(t *testing.T) {
	d := DistanceUnderProfile(profileByName(t, "empirical"), 5)
	if d.PhysicalPerLogical != 0 || d.LogicalPerProcessor != 0 ||
		d.ProcessorsForBitcoin != 0 || d.PhysicalQubitsForBitcoin != 0 ||
		d.MaxCurveBitsPerProcessor != 0 {
		t.Fatalf("empirical profile leaked hardware fields: %+v", d)
	}
	want := 100 * 5.0 / float64(BitcoinLogicalThreshold)
	if math.Abs(d.DistancePercent-want) > 1e-9 {
		t.Fatalf("distance = %f, want %f", d.DistancePercent, want)
	}
}

// TestDistancePercentIsIdenticalAcrossProfiles: assumptions may re-price the
// threshold but must never move the demonstrated clock.
func TestDistancePercentIsIdenticalAcrossProfiles(t *testing.T) {
	report := DistanceReport(7)
	if len(report) != len(QECProfiles()) {
		t.Fatalf("report has %d entries, want %d", len(report), len(QECProfiles()))
	}
	for _, d := range report {
		if d.DemonstratedLevel != 7 {
			t.Fatalf("profile %s demonstrated level = %d, want 7", d.Profile, d.DemonstratedLevel)
		}
		if d.DistancePercent != report[0].DistancePercent {
			t.Fatalf("profile %s distance %f differs from %f", d.Profile, d.DistancePercent, report[0].DistancePercent)
		}
	}
}

// TestDistanceNegativeLevelClamped: a negative demonstrated level is treated
// as zero rather than producing a negative distance.
func TestDistanceNegativeLevelClamped(t *testing.T) {
	d := DistanceUnderProfile(profileByName(t, "empirical"), -3)
	if d.DemonstratedLevel != 0 || d.DistancePercent != 0 {
		t.Fatalf("negative level not clamped: %+v", d)
	}
}
