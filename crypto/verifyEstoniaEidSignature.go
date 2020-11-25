package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/sha3"
)

const (
	publicKeyHex = "04acf16bf960e6797993a7fd08ad4464fde0b7eefe543d119552c4d1e786dd851903afe925ac1414cefaac741c5200fa92c5f37a30a87430fc59bb543ff768a3cbc934548774b5645b2c3209b2a928c1cb7b52c2bb973690dddf7c348585907b27"
	messageRaw   = "testing verification signature"
	signatureHex = "00B87DCEC8616E0BC01D84A903B77E4BD70F7812378DDD90EF2F7253B011E49E49E8F4544E5F470227FE406E26B4A104BEDE622BC94689381C07E651CA53C1EB55160B6DB55B4E075C1289BE791CB485751E135B010DC52FE146CAB4ED31FF3F"
)

func hashMessage(message string) []byte {
	messsageByte := []byte(message)

	digest := sha3.New256()
	_, err := digest.Write(messsageByte)
	if err != nil {
		fmt.Printf("message hashing error: %v", err)
		os.Exit(1)
	}
	return digest.Sum([]byte{})
}

func testVerifyNIST384P() {
	// using the same key over and over again
	var (
		privateKeyString = "31411050219761469148894615220884268065173260688609241211538077982968835223418928466360232202329446679639159833310055"
		publicKey        ecdsa.PublicKey
		privateKey       ecdsa.PrivateKey
	)
	publicKeyHex := "040b57080d1ebc7baffd8a1eca6a2ae1ab568878e75d3ea68c0962f775ae81b2cc508cb2b1851774ed096f7420582693aff309c62899e324b1bb4cce8ac6e4fa2058d3678fdec6ee3fca8c87cf24bf376f5fbfac52e2ca356f157da3a950ce9eaa"
	publicKeyBytes, _ := hex.DecodeString(publicKeyHex)
	curve := elliptic.P384()
	publicKey.Curve = curve
	publicKey.X, publicKey.Y = elliptic.Unmarshal(curve, publicKeyBytes)

	privateKeyD := new(big.Int)
	_, _ = privateKeyD.SetString(privateKeyString, 10)
	privateKey.PublicKey = publicKey
	privateKey.D = privateKeyD
	privateKeyAdd := &privateKey
	publicKeyAdd := &publicKey

	// // generating new keys
	// curve := elliptic.P384()
	// privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	// if err != nil {
	// 	fmt.Printf("Failed generating private key")
	// 	os.Exit(1)
	// }
	// publicKey := privateKey.Public().(*ecdsa.PublicKey)
	// privateKeyAdd := privateKey
	// publicKeyAdd := publicKey

	messsageByte := hashMessage(messageRaw)

	// decoding signature from hex string to bytes
	signatureByte, err := hex.DecodeString(signatureHex)
	if err != nil {
		fmt.Printf("signature parsing error: %v", err)
		os.Exit(1)
	}

	signature, err := ecdsa.SignASN1(rand.Reader, privateKeyAdd, messsageByte)
	if err != nil {
		fmt.Printf("Signing error: %v", err)
		os.Exit(1)
	}

	result := ecdsa.VerifyASN1(publicKeyAdd, messsageByte, signature)
	fmt.Println("result     : ", result)
	fmt.Println("privateKey : ", privateKey.D.String())
	fmt.Println("signature  : ", hex.EncodeToString(signature), len(signature))
	fmt.Println("signatureE : ", hex.EncodeToString(signatureByte), len(signatureByte))
	fmt.Println("public key : ", hex.EncodeToString(elliptic.Marshal(publicKeyAdd.Curve, publicKeyAdd.X, publicKeyAdd.Y)))
}

func loadPublicKeyFromPem() (publicKey ecdsa.PublicKey) {
	certificatePem := `
-----BEGIN CERTIFICATE-----
MIIDzjCCAzCgAwIBAgIQCRxwO6tzCWdc73UTenfjrDAKBggqhkjOPQQDBDBYMQsw
CQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRh
DA5OVFJFRS0xMDc0NzAxMzETMBEGA1UEAwwKRVNURUlEMjAxODAeFw0xOTA1MzAw
NjE1NDdaFw0yNDA1MjkyMTU5NTlaMHcxCzAJBgNVBAYTAkVFMSYwJAYDVQQDDB1D
QVBPRElFQ0ksUk9CRVJUTywzNzQwNjI1MDE2MDESMBAGA1UEBAwJQ0FQT0RJRUNJ
MRAwDgYDVQQqDAdST0JFUlRPMRowGAYDVQQFExFQTk9FRS0zNzQwNjI1MDE2MDB2
MBAGByqGSM49AgEGBSuBBAAiA2IABKzxa/lg5nl5k6f9CK1EZP3gt+7+VD0RlVLE
0eeG3YUZA6/pJawUFM76rHQcUgD6ksXzejCodDD8WbtUP/doo8vJNFSHdLVkWywy
CbKpKMHLe1LCu5c2kN3ffDSFhZB7J6OCAZ4wggGaMAkGA1UdEwQCMAAwDgYDVR0P
AQH/BAQDAgZAMEgGA1UdIARBMD8wMgYLKwYBBAGDkSEBAQQwIzAhBggrBgEFBQcC
ARYVaHR0cHM6Ly93d3cuc2suZWUvQ1BTMAkGBwQAi+xAAQIwHQYDVR0OBBYEFI3A
VTKnMdqw1j/upmDPfzO1AQ//MIGKBggrBgEFBQcBAwR+MHwwCAYGBACORgEBMAgG
BgQAjkYBBDATBgYEAI5GAQYwCQYHBACORgEGATBRBgYEAI5GAQUwRzBFFj9odHRw
czovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNl
cnRpZmljYXRlcy8TAkVOMB8GA1UdIwQYMBaAFNmscNtffr6U+KDkvkei0DStmioS
MGYGCCsGAQUFBwEBBFowWDAnBggrBgEFBQcwAYYbaHR0cDovL2FpYS5zay5lZS9l
c3RlaWQyMDE4MC0GCCsGAQUFBzAChiFodHRwOi8vYy5zay5lZS9lc3RlaWQyMDE4
LmRlci5jcnQwCgYIKoZIzj0EAwQDgYsAMIGHAkIBICcDVSlZ2I/+A5SGrS1mNpQy
W8Amz1EUslE5PkQ5kWlEId2jNfXTa48GiZYDE8sOBDu36xd+LH2N+EtJj2/SubAC
QXsj+LaIjP1Cu3JccZ0+132dJxf3PhanZ4cmp2Q4Qmta0hQ7NlV0tl+MFFJASU0c
vGGclxtDy+1uDwnqtDB5wYbg
-----END CERTIFICATE-----`

	// decode the key, assuming it's in PEM format
	block, _ := pem.Decode([]byte(certificatePem))
	if block == nil {
		fmt.Printf("Failed to decode PEM public key")
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Printf("Failed to parse certificate: %v", err)
		os.Exit(1)
	}
	pub := cert.PublicKey
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		publicKey = *pub
	default:
		fmt.Printf("Unsupported public key type")
		os.Exit(1)
	}
	return
}

func loadPublicKeyFromDer() (publicKey ecdsa.PublicKey) {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		fmt.Printf("public key parsing error: %v", err)
		os.Exit(1)
	}
	curve := elliptic.P384()
	publicKey.Curve = curve
	publicKey.X, publicKey.Y = elliptic.Unmarshal(curve, publicKeyBytes)
	return publicKey
}

// source: https://github.com/warner/python-ecdsa/blob/master/src/ecdsa/util.py (sigdecode_string)
// return: r, s, error
func decodeSignatureNIST384RS(signature []byte) (*big.Int, *big.Int, error) {
	// curveOrder := "39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643"
	curveOrderLen := 48
	if len(signature) != curveOrderLen*2 {
		return nil, nil, errors.New(fmt.Sprintf("error signature length: %d", len(signature)))
	}
	rBytes := signature[:48]
	sBytes := signature[48:]
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	return r, s, nil
}

func verifyEidSignature() {
	publicKey := loadPublicKeyFromDer()
	messsageByte := hashMessage(messageRaw)

	// decoding signature from hex string to bytes
	signatureByte, err := hex.DecodeString(signatureHex)
	if err != nil {
		fmt.Printf("signature parsing error: %v", err)
		os.Exit(1)
	}

	r, s, _ := decodeSignatureNIST384RS(signatureByte)
	result := ecdsa.Verify(&publicKey, messsageByte, r, s)
	fmt.Println("result     : ", result)
	fmt.Println("public key : ", hex.EncodeToString(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)))
}

func main() {
	verifyEidSignature()
}
