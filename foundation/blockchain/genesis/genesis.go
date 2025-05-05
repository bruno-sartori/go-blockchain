package genesis

import (
	"encoding/json"
	"os"
	"time"
)

type Genesis struct {
	Date          time.Time         `json:"date"`
	ChainID       uint16            `json:"chain_id"`        // Unique identifier for the blockchain
	TransPerBlock uint16            `json:"trans_per_block"` // Maximum number of transactions per block
	Difficulty    uint16            `json:"difficulty"`      // Difficulty of the proof-of-work algorithm
	MiningReward  uint64            `json:"mining_reward"`   // Reward for mining a block
	GasPrice      uint64            `json:"gas_price"`       // Fee paid for each transaction
	Balances      map[string]uint64 `json:"balances"`
}

// =============================================================================

// Opens and consumes the genesis file
func load() (Genesis, error) {
	path := "zblock/genesis.json"
	content, err := os.ReadFile(path)
	if err != nil {
		return Genesis{}, err
	}

	var genesis Genesis
	err = json.Unmarshal(content, &genesis)
	if err != nil {
		return Genesis{}, err
	}

	return genesis, nil
}
