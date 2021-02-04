// package main

// import (
// 	"encoding/hex"

// 	"github.com/ethereum/go-ethereum/crypto"
// )

// func main() {
// 	// privateKey: 4cc7644e52bce7b5f9e34dac78d88889b95833d75294ce6d49b3030229f9d527
// 	payload, _ := hex.DecodeString("0100000001df6f1b60000000000400000011f2b30c9479ccaa639962e943ca7cfd3498705258ddb49dfe25bba00a555e48cb35a79f3d084ce26dbac0e6bb887463774817cb80e89b20c0990bc47f9075d500000000e12c84a0fd461cbbec5956a66b2ebad0499491cff77f75b583d041d757d87fff00e1f505000000000800000000e1f505000000000200000000000000")
// 	signature, _ := hex.DecodeString("c79984b222e95f095df054be5533fbc92f95f078b375d2985472bc96012176da2442dcbfe274ffe6a0f4bf31bfc6093554aae00f105a37add43257c569eb8fe91c")
// 	publicKey, _ := hex.DecodeString("0411f2b30c9479ccaa639962e943ca7cfd3498705258ddb49dfe25bba00a555e48cb35a79f3d084ce26dbac0e6bb887463774817cb80e89b20c0990bc47f9075d5")
// 	hash := crypto.Keccak256Hash(payload)

// 	// sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), signature)
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	// verified := bytes.Equal(sigPublicKey, publicKey)

// 	signatureNoRecoverID := signature[:len(signature)-1] // remove recovery id
// 	verified := crypto.VerifySignature(publicKey, hash.Bytes(), signatureNoRecoverID)
// 	println("isVerified:")
// 	println(verified)
// }

package main

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Println("publicKey:", hexutil.Encode(publicKeyBytes))

	publicKeyHash := crypto.Keccak256Hash(publicKeyBytes[1:])
	addressLen := 32
	fmt.Println("address:", hexutil.Encode(publicKeyHash[addressLen-20:]))

	data := []byte("hello")
	hash := crypto.Keccak256Hash(data)
	fmt.Println("hash:", hash.Hex()) // 0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("signature:", hexutil.Encode(signature)) // 0x789a80053e4927d0a898db8e065e948f5cf086e32f9ccaa54c1908e22ac430c62621578113ddbb62d509bf6049b8fb544ab06d36f916685a2eb8e57ffadde02301

	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), signature)
	if err != nil {
		log.Fatal(err)
	}

	matches := bytes.Equal(sigPublicKey, publicKeyBytes)
	fmt.Println("matches:", matches) // true

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), signature)
	if err != nil {
		log.Fatal(err)
	}

	sigPublicKeyBytes := crypto.FromECDSAPub(sigPublicKeyECDSA)
	matches = bytes.Equal(sigPublicKeyBytes, publicKeyBytes)
	fmt.Println("matches:", matches) // true

	signatureNoRecoverID := signature[:len(signature)-1] // remove recovery id
	verified := crypto.VerifySignature(publicKeyBytes, hash.Bytes(), signatureNoRecoverID)
	fmt.Println("verified:", verified) // true
}
