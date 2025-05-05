package main

import (
	"fmt"
	"log"

	"github.com/bruno-sartori/go-blockchain/foundation/blockchain/signature"
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
	fmt.Println(hash)

	v.Value = 11
	hash = signature.Hash(v)
	fmt.Println(hash)

	return nil
}
