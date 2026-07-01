package qlab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// DefaultChainPath is the local file that stores the append-only event chain.
// It is intentionally a local, non-committed file.
const DefaultChainPath = "qlabcoin-chain.json"

// ZeroHash is the prev_hash anchor of the genesis block (64 hex zeros).
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Event types recorded on the chain. Each high-level lifecycle change becomes
// one event in one new block (1 event = 1 block), keeping the chain auditable.
const (
	EventSubmit EventType = "submit" // a verified solution was accepted
	EventHarden EventType = "harden" // mitigation applied (broken -> hardened)
	EventReopen EventType = "reopen" // level reopened, next level opened
)

// EventType labels a chain event.
type EventType string

// Event is one recorded lifecycle change for a level.
type Event struct {
	Type       EventType   `json:"type"`
	Level      int         `json:"level"`
	Submission *Submission `json:"submission,omitempty"` // present only for EventSubmit
	Timestamp  string      `json:"timestamp"`            // RFC3339 UTC
}

// Block is one link in the chain. The genesis block has Index 0, PrevHash
// ZeroHash and no events; it anchors the chain and never mutates.
type Block struct {
	Index    int     `json:"index"`
	PrevHash string  `json:"prev_hash"` // hash of the previous block (ZeroHash for genesis)
	Events   []Event `json:"events"`
	Nonce    int     `json:"nonce,omitempty"` // reserved for future use; currently 0
}

// chainFile is the on-disk JSON layout.
type chainFile struct {
	Blocks []Block `json:"blocks"`
}

// Chain is an append-only log of blocks, persisted as a single JSON file. It is
// the single source of truth; the live registry is derived from it.
type Chain struct {
	path   string
	blocks []Block
}

// NewChain returns a chain backed by path. The file is not touched until Load.
func NewChain(path string) *Chain {
	if path == "" {
		path = DefaultChainPath
	}
	return &Chain{path: path}
}

// Load reads the chain file. A missing file is not an error: a chain with only
// the genesis block is created in memory (and persisted on the next Save).
func (c *Chain) Load() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.blocks = []Block{genesisBlock()}
			return nil
		}
		return err
	}
	var f chainFile
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("parse chain %s: %w", c.path, err)
	}
	if len(f.Blocks) == 0 {
		f.Blocks = []Block{genesisBlock()}
	}
	// Defensively ensure block 0 is a well-formed genesis anchor.
	if f.Blocks[0].Index != 0 || f.Blocks[0].PrevHash != ZeroHash {
		return fmt.Errorf("chain %s: block 0 is not a valid genesis anchor", c.path)
	}
	c.blocks = f.Blocks
	return nil
}

// Save writes the chain atomically (temp file + rename). Blocks keep their
// stored order; nothing is sorted because order is meaningful here.
func (c *Chain) Save() error {
	out := chainFile{Blocks: c.blocks}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// Append adds one new block containing exactly the given event, chaining it to
// the current last block. It returns the appended block. The caller is
// responsible for calling Save.
func (c *Chain) Append(e Event) (Block, error) {
	prev := c.last()
	blk := Block{
		Index:    prev.Index + 1,
		PrevHash: BlockHash(prev),
		Events:   []Event{e},
	}
	c.blocks = append(c.blocks, blk)
	return blk, nil
}

// Blocks returns every block including the genesis block. The returned slice is
// a copy; callers may not mutate chain state through it.
func (c *Chain) Blocks() []Block {
	out := make([]Block, len(c.blocks))
	copy(out, c.blocks)
	return out
}

// LastHash returns the hash of the last block (the value the next block must
// chain to). For an unmodified chain this is the hash of the genesis block.
func (c *Chain) LastHash() string {
	return BlockHash(c.last())
}

// Verify re-walks the chain and checks that every non-genesis block chains to
// the hash of its predecessor. It does not validate event semantics; use
// DeriveRegistry for that.
func (c *Chain) Verify() error {
	if len(c.blocks) == 0 {
		return errors.New("chain has no genesis block")
	}
	if c.blocks[0].Index != 0 || c.blocks[0].PrevHash != ZeroHash {
		return errors.New("genesis block is malformed")
	}
	for i := 1; i < len(c.blocks); i++ {
		wantIndex := i
		if c.blocks[i].Index != wantIndex {
			return fmt.Errorf("block %d: index is %d", i, c.blocks[i].Index)
		}
		wantPrev := BlockHash(c.blocks[i-1])
		if c.blocks[i].PrevHash != wantPrev {
			return fmt.Errorf("block %d: prev_hash mismatch (want %s, got %s)", i, wantPrev, c.blocks[i].PrevHash)
		}
	}
	return nil
}

func (c *Chain) last() Block {
	if len(c.blocks) == 0 {
		return genesisBlock()
	}
	return c.blocks[len(c.blocks)-1]
}

func genesisBlock() Block {
	return Block{Index: 0, PrevHash: ZeroHash, Events: nil}
}

// BlockHash is the deterministic hash of a block: sha256 over the prev_hash and
// the canonical (lexicographically-keyed) JSON of its events. Nonce is excluded
// so that the field can be used later without re-defining the chain identity.
func BlockHash(b Block) string {
	payload, _ := json.Marshal(eventsCanonical{PrevHash: b.PrevHash, Events: b.Events})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// eventsCanonical is a stable payload shape for hashing. Field order matters: by
// keeping PrevHash first, the hash binds each block to its predecessor.
type eventsCanonical struct {
	PrevHash string  `json:"prev_hash"`
	Events   []Event `json:"events"`
}
