package qlab

import (
	"path/filepath"
	"testing"
)

func newTestChain(t *testing.T) *Chain {
	t.Helper()
	c := NewChain(filepath.Join(t.TempDir(), "chain.json"))
	if err := c.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestChainLoadMissingFileCreatesGenesis(t *testing.T) {
	c := newTestChain(t)
	blocks := c.Blocks()
	if len(blocks) != 1 {
		t.Fatalf("expected 1 genesis block, got %d", len(blocks))
	}
	g := blocks[0]
	if g.Index != 0 || g.PrevHash != ZeroHash || len(g.Events) != 0 {
		t.Fatalf("malformed genesis: %+v", g)
	}
}

func TestChainAppendChainsToPrev(t *testing.T) {
	c := newTestChain(t)
	prevHash := c.LastHash()
	blk, err := c.Append(Event{Type: EventSubmit, Level: 5, Timestamp: "2026-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if blk.Index != 1 {
		t.Fatalf("index = %d, want 1", blk.Index)
	}
	if blk.PrevHash != prevHash {
		t.Fatalf("prev_hash = %s, want genesis hash %s", blk.PrevHash, prevHash)
	}
	if c.LastHash() == prevHash {
		t.Fatal("LastHash did not change after append")
	}
	if len(c.Blocks()) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(c.Blocks()))
	}
}

func TestChainVerifyAcceptsFreshChain(t *testing.T) {
	c := newTestChain(t)
	_, _ = c.Append(Event{Type: EventSubmit, Level: 5, Timestamp: "t"})
	_, _ = c.Append(Event{Type: EventHarden, Level: 5, Timestamp: "t"})
	if err := c.Verify(); err != nil {
		t.Fatalf("Verify rejected fresh chain: %v", err)
	}
}

// TestChainVerifyRejectsTamperedEvent: editing a recorded event must break the
// hash of its block and therefore the link of the following block.
func TestChainVerifyRejectsTamperedEvent(t *testing.T) {
	c := newTestChain(t)
	_, _ = c.Append(Event{Type: EventSubmit, Level: 5, Timestamp: "t"})
	_, _ = c.Append(Event{Type: EventHarden, Level: 5, Timestamp: "t"})

	// Tamper with the first real block's event (change level 5 -> 6).
	blocks := c.blocks
	blocks[1].Events[0].Level = 6
	if err := c.Verify(); err == nil {
		t.Fatal("Verify accepted a chain with a tampered event")
	}
}

// TestChainVerifyRejectsBrokenLink: editing a prev_hash must be detected.
func TestChainVerifyRejectsBrokenLink(t *testing.T) {
	c := newTestChain(t)
	_, _ = c.Append(Event{Type: EventSubmit, Level: 5, Timestamp: "t"})
	c.blocks[1].PrevHash = "deadbeef"
	if err := c.Verify(); err == nil {
		t.Fatal("Verify accepted a chain with a broken prev_hash link")
	}
}

func TestBlockHashDeterministic(t *testing.T) {
	a := Block{Index: 1, PrevHash: ZeroHash, Events: []Event{{Type: EventHarden, Level: 5, Timestamp: "t"}}}
	b := a // shallow copy is fine: events slice is not mutated by hashing
	if BlockHash(a) != BlockHash(b) {
		t.Fatal("identical blocks produced different hashes")
	}
	// Different timestamp must yield a different hash.
	other := a
	other.Events = []Event{{Type: EventHarden, Level: 5, Timestamp: "other"}}
	if BlockHash(a) == BlockHash(other) {
		t.Fatal("distinct blocks produced the same hash")
	}
}

func TestChainSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chain.json")
	c1 := NewChain(path)
	_ = c1.Load()
	_, _ = c1.Append(Event{Type: EventSubmit, Level: 5, Timestamp: "t"})
	if err := c1.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	c2 := NewChain(path)
	if err := c2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c1.LastHash() != c2.LastHash() {
		t.Fatalf("LastHash differs after round-trip: %s vs %s", c1.LastHash(), c2.LastHash())
	}
	if err := c2.Verify(); err != nil {
		t.Fatalf("reloaded chain failed Verify: %v", err)
	}
}
