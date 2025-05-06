package signature

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const ZeroHash string = "0x0000000000000000000000000000000000000000000000000000000000000000"

// sartoriCoinID is an arbitrary number for signing messages. This will make it
// clear that the signature comes for the Sartori blockchain.
// Ethereum and Bitcoin do this as well, but they use the value of 27.
const sartoriCoinID = 29

func Hash(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ZeroHash
	}

	hash := sha256.Sum256(data)
	return hexutil.Encode(hash[:])
}

func ToSignatureBytes(v, r, s *big.Int) []byte {
	sig := make([]byte, crypto.SignatureLength)

	rBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	copy(sig, rBytes)

	sBytes := make([]byte, 32)
	s.FillBytes(sBytes)
	copy(sig[32:], sBytes)

	sig[64] = byte(v.Uint64() - sartoriCoinID)

	return sig
}

func ToSignatureBytesWithSartoriCoinID(v, r, s *big.Int) []byte {
	sig := ToSignatureBytes(v, r, s)
	sig[64] = byte(v.Uint64())

	return sig
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

func toSignatureValues(sig []byte) (v, r, s *big.Int) {
	r = big.NewInt(0).SetBytes(sig[:32])
	s = big.NewInt(0).SetBytes(sig[32:64])
	v = big.NewInt(0).SetBytes([]byte{sig[64] + sartoriCoinID})

	return v, r, s
}

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

func VerifySignature(v, r, s *big.Int) error {
	// Check the recovery id is either 0 or 1
	uintV := v.Uint64() - sartoriCoinID
	if uintV != 0 && uintV != 1 {
		return errors.New("invalid recover id")
	}

	if !crypto.ValidateSignatureValues(byte(uintV), r, s, false) {
		return errors.New("invalid signature values")
	}

	return nil
}

func FromAddress(value any, v, r, s *big.Int) (string, error) {
	// Prepare the data for public key extraction
	data, err := salt(value)
	if err != nil {
		return "", err
	}

	// Convert the [R|S|V] format into the riginal 65 bytes
	sig := ToSignatureBytes(v, r, s)

	// Capture the public key assoociated with this data and signature
	publicKey, err := crypto.SigToPub(data, sig)
	if err != nil {
		return "", err
	}

	// Extract the account address from the public key.
	return crypto.PubkeyToAddress(*publicKey).String(), nil
}

func SignatureString(v, r, s *big.Int) string {
	return hexutil.Encode(ToSignatureBytesWithSartoriCoinID(v, r, s))
}
