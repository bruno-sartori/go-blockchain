package signature

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// sartoriCoinID is an arbitrary number for signing messages. This will make it
// clear that the signature comes for the Sartori blockchain.
// Ethereum and Bitcoin do this as well, but they use the value of 27.
const sartoriCoinID = 29

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

func toSignatureValues(sig []byte) (v, r, s *big.Int) {
	r = big.NewInt(0).SetBytes(sig[:32])
	s = big.NewInt(0).SetBytes(sig[32:64])
	v = big.NewInt(0).SetBytes([]byte{sig[64] + sartoriCoinID})

	return v, r, s
}

// Uses the specified private key to sign the transaction.
func Sign(value any, privateKey *ecdsa.PrivateKey) (v, r, s *big.Int, err error) {
	// Prepare the data for signing.
	data, err := salt(value)
	if err != nil {
		return nil, nil, nil, err
	}

	// Sign the hash with the private key to produce a signature.
	sig, err := crypto.Sign(data, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Extract the bytes for the original public key.
	publicKeyOrg := privateKey.Public()
	publicKeyECDSA, ok := publicKeyOrg.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, errors.New("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	// Check the public key validates the data and signature.
	rs := sig[:crypto.RecoveryIDOffset]
	if !crypto.VerifySignature(publicKeyBytes, data, rs) {
		return nil, nil, nil, errors.New("invalid signature produced")
	}

	// Convert the 65 byte signature into the [R|S|V] format.
	v, r, s = toSignatureValues(sig)

	return v, r, s, nil
}
