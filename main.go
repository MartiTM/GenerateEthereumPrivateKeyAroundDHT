package main

import (
	"crypto/ecdsa"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func main() {
	
	nbPeers, communBits := getArgs()

	bits := int(math.Pow(2, float64(communBits)))

	peersByBit := nbPeers / bits

	array := make(map[string]int, bits)
	res := make([]ecdsa.PrivateKey, 0, nbPeers)

	for i := range array {
		array[i] = 0
	}

	fmt.Printf("nbPeers %v\n", nbPeers)
	fmt.Printf("communBits %v\n", communBits)
	fmt.Printf("bits %v\n", bits)
	fmt.Printf("peersByBit %v\n", peersByBit)
	
		
	for len(res) < bits*peersByBit{
		
		key, _ := crypto.GenerateKey()
		id := enode.PubkeyToIDV4(&key.PublicKey)

		firstNBits := getNFirstBits(id, communBits)

		if array[firstNBits] < peersByBit {
			array[firstNBits]++
			res = append(res, *key)
			fmt.Printf("Trouvé, bits : %v, total : %v\n", firstNBits, array[firstNBits])
			fmt.Printf("Manque %v clé\n", bits*peersByBit-len(res))
		}
	}

	// pour le reste
	for len(res) < nbPeers {
		key, _ := crypto.GenerateKey()
		res = append(res, *key)
	}

	// ecrire les clés 
	
	const datadirPrivateKey      = "nodekey"            // Path within the datadir to the node's private key
	for i, key := range(res) {
		fmt.Printf("key %v : %08b\n", i, enode.PubkeyToIDV4(&key.PublicKey))
		name := "key"+fmt.Sprint(i+1)
		instanceDir := filepath.Join("./KEY", name)
		if err := os.MkdirAll(instanceDir, 0700); err != nil {
			fmt.Println(fmt.Sprintf("Failed to persist node key: %v", err))
		}
		keyfile := filepath.Join(instanceDir, datadirPrivateKey)
		if err := crypto.SaveECDSA(keyfile, &key); err != nil {
			fmt.Println(fmt.Sprintf("Failed to persist node key: %v", err))
		}
	}
}

func getNFirstBits(id [32]byte, n int) (string) {

	idInBit := fmt.Sprintf("%08b", id)

	idFiltered := ""
	for i := range idInBit {
		if idInBit[i] == '0' || idInBit[i] == '1' {
			idFiltered += string(idInBit[i])
		}
	}

	firstNBits := idFiltered[:n]

	return firstNBits
}

func getArgs() (int, int) {
	argsWithoutProg := os.Args[1:]

	if len(argsWithoutProg) != 2 {
		panic("need 2 args")
	}

	nbPeers, err := strconv.Atoi(argsWithoutProg[0]) 
	communBits, err1 := strconv.Atoi(argsWithoutProg[1])

	if err != nil || err1 != nil {
		panic("no int arg")
	}

	if math.Pow(2, float64(communBits)) > float64(nbPeers) {
		panic("2^communBits > nbPeers")
	}

	return nbPeers, communBits
}