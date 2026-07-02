package qlab

import (
	"strings"
	"testing"
)

// dashboardFromLifecycle builds a chain with the full level-5 lifecycle
// (submit, harden, reopen, one reproduction) and returns its dashboard.
func dashboardFromLifecycle(t *testing.T) Dashboard {
	t.Helper()
	c := chainWithBrokenLevel5(t)
	_, _ = c.Append(Event{Type: EventHarden, Level: 5, Timestamp: "t"})
	_, _ = c.Append(Event{Type: EventReopen, Level: 5, Timestamp: "t"})
	rep := &Reproduction{Author: "test-author", CircuitHash: "sha256:rep", Result: ReproductionReproduced}
	repEv := signTestEvent(t, Event{Type: EventReproduce, Level: 5, Reproduction: rep, Timestamp: "t"})
	_, _ = c.Append(repEv)
	r, err := DeriveRegistry(c)
	if err != nil {
		t.Fatalf("DeriveRegistry: %v", err)
	}
	return BuildDashboard(c, r, "2026-07-02T00:00:00Z")
}

func TestBuildDashboardLifecycle(t *testing.T) {
	d := dashboardFromLifecycle(t)
	if d.MaxBrokenLevel != 5 {
		t.Fatalf("max broken = %d, want 5", d.MaxBrokenLevel)
	}
	if d.MaxBrokenFamily != "toy-order-finding" {
		t.Fatalf("family = %q, want toy-order-finding", d.MaxBrokenFamily)
	}
	if d.TotalReproductions != 1 {
		t.Fatalf("reproductions = %d, want 1", d.TotalReproductions)
	}
	if len(d.OpenLevels) != 1 || d.OpenLevels[0] != 6 {
		t.Fatalf("open levels = %v, want [6]", d.OpenLevels)
	}
	if d.MitigationMode != ModeC {
		t.Fatalf("mode = %s, want C (level 5 broken)", d.MitigationMode)
	}
	if d.Blocks != 6 { // genesis + register + submit + harden + reopen + reproduce
		t.Fatalf("blocks = %d, want 6", d.Blocks)
	}
	if len(d.Distances) != len(QECProfiles()) {
		t.Fatalf("distances = %d entries, want %d", len(d.Distances), len(QECProfiles()))
	}
}

// TestBuildDashboardFresh: a genesis-only chain yields an honest zero state
// with level 1 as the frontier.
func TestBuildDashboardFresh(t *testing.T) {
	c := newTestChain(t)
	r, err := DeriveRegistry(c)
	if err != nil {
		t.Fatalf("DeriveRegistry: %v", err)
	}
	d := BuildDashboard(c, r, "2026-07-02T00:00:00Z")
	if d.MaxBrokenLevel != 0 || d.DistancePercent != 0 {
		t.Fatalf("fresh dashboard not zeroed: %+v", d)
	}
	if len(d.OpenLevels) != 1 || d.OpenLevels[0] != 1 {
		t.Fatalf("fresh frontier = %v, want [1]", d.OpenLevels)
	}
	if d.MitigationMode != ModeA {
		t.Fatalf("fresh mode = %s, want A", d.MitigationMode)
	}
}

func TestRenderTextContainsKeyFacts(t *testing.T) {
	txt := dashboardFromLifecycle(t).RenderText()
	for _, want := range []string{
		"Qlabcoin Quantum Clock",
		"Highest broken level      : 5 (toy-order-finding)",
		"Mode C",
		"2330 logical qubits",
		"optimistic",
		"conservative",
		"empirical",
		"demonstrated logical attack qubits",
	} {
		if !strings.Contains(txt, want) {
			t.Fatalf("text dashboard missing %q:\n%s", want, txt)
		}
	}
}

func TestRenderHTMLIsSelfContained(t *testing.T) {
	html, err := dashboardFromLifecycle(t).RenderHTML()
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	for _, want := range []string{
		"<!DOCTYPE html>",
		"Qlabcoin Quantum Clock",
		"2330",
		"optimistic",
		"conservative",
		"empirical",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("html dashboard missing %q", want)
		}
	}
	// Self-contained: no external stylesheet, script, or image references.
	for _, forbidden := range []string{"<script", "src=", "href="} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("html dashboard must be self-contained, found %q", forbidden)
		}
	}
}
