package signature

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
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

// Returns a hash of 32 bytes that represents this data with
// the salt embedded into the final hash
func salt(value any) ([]byte, error) {
	v, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	// This salt/stamp is used so signatures we produce when signing data
	// are always unique to the blockchain
	salt := []byte(fmt.Sprintf("\x19SartoriCoin Signed Message:\n%d", len(v)))

	// Hash the salt and txHash together in a final 32 byte array
	// that rerpresents the data
	data := crypto.Keccak256(salt, v)

	return data, nil
}
