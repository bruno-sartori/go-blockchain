package signature

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

const ZeroHash string = "0x0000000000000000000000000000000000000000000000000000000000000000"

func Hash(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ZeroHash
	}

	hash := sha256.Sum256(data)
	return hexutil.Encode(hash[:])
}
