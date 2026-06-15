package snowflake

import (
	"fmt"
	"sync"
	"time"
)

const (
	epoch         = int64(1700000000000) // Custom epoch: 2023-11-14
	nodeBits      = uint(10)
	sequenceBits  = uint(12)
	nodeMax       = -1 ^ (-1 << nodeBits)
	sequenceMask  = -1 ^ (-1 << sequenceBits)
	nodeShift     = sequenceBits
	timestampShift = nodeBits + sequenceBits
)

// Generator generates unique snowflake IDs.
type Generator struct {
	mu        sync.Mutex
	nodeID    int64
	timestamp int64
	sequence  int64
}

// New creates a new snowflake ID generator.
func New(nodeID int64) (*Generator, error) {
	if nodeID < 0 || nodeID > int64(nodeMax) {
		return nil, fmt.Errorf("node ID must be between 0 and %d", nodeMax)
	}
	return &Generator{nodeID: nodeID}, nil
}

// Generate produces a new unique ID.
func (g *Generator) Generate() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now().UnixMilli() - epoch

	if now == g.timestamp {
		g.sequence = (g.sequence + 1) & int64(sequenceMask)
		if g.sequence == 0 {
			// Wait for next millisecond
			for now <= g.timestamp {
				now = time.Now().UnixMilli() - epoch
			}
		}
	} else {
		g.sequence = 0
	}

	g.timestamp = now

	return (now << timestampShift) | (g.nodeID << int64(nodeShift)) | g.sequence
}
