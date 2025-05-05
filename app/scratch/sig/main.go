package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/bruno-sartori/go-blockchain/foundation/blockchain/signature"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type tx struct {
	From  string
	To    string
	Value int
}

func main() {
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {
	v := tx{
		From:  "Bill",
		To:    "Bruno",
		Value: 10,
	}

	hash := signature.Hash(v)
	fmt.Println("SUM 1", hash)

	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	khash := crypto.Keccak256(data)
	fmt.Println("KEC 1", hexutil.Encode(khash[:]))

	v.Value = 11
	hash = signature.Hash(v)
	fmt.Println("SUM 2", hash)

	data, err = json.Marshal(v)
	if err != nil {
		return err
	}

	khash = crypto.Keccak256(data)
	fmt.Println("KEC 2", hexutil.Encode(khash[:]))

	return nil
}
