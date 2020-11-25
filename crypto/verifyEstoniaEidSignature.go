package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

type ECDSASignature struct {
	R, S *big.Int
}

const (
	publicKeyHex     = "04acf16bf960e6797993a7fd08ad4464fde0b7eefe543d119552c4d1e786dd851903afe925ac1414cefaac741c5200fa92c5f37a30a87430fc59bb543ff768a3cbc934548774b5645b2c3209b2a928c1cb7b52c2bb973690dddf7c348585907b27"
	messageRaw       = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum."
	messageHex       = "7321348c8894678447b54c888fdbc4e4b825bf4d1eb0cfb27874286a23ea9fd2"
	signatureHex     = "06c57ba074f7de0b0d46f7c81e57cd183c728af50eb96a1e5bd3d489a662a174afd99f4e64238ef95d8433521423047b4b9e724552e398ff77fbeb2e850fcd76c91f6664ee248b542967108000e5325b6a278428218c643635118a6acccc4c38"
	signatureRString = "1042216562530904695980748562657912478819164596514687731926287790267732122247375403785367634558258330019697369744507"
	signatureSString = "11638818723068440459844038883977416710408940638415319804492170875859702666650399918084976194012226024185515247160376"
	publicKeyPem     = `
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
)

var (
	err            error
	signatureByte  []byte
	publicKeyBytes []byte
	messsageByte   []byte
	publicKey      ecdsa.PublicKey
)

func init() {
	publicKeyBytes, err = hex.DecodeString(publicKeyHex)
	if err != nil {
		fmt.Printf("public key parsing error: %v", err)
		os.Exit(1)
	}

	signatureByte, err = hex.DecodeString(signatureHex)
	if err != nil {
		fmt.Printf("signature parsing error: %v", err)
		os.Exit(1)
	}
}

func useMessageRaw() {
	messsageByte = []byte(messageRaw)
}

func useMessageHex() {
	messsageByte, err = hex.DecodeString(messageHex)
	if err != nil {
		fmt.Printf("message parsing error: %v", err)
		os.Exit(1)
	}
}

func verifyNormally() bool {
	var (
		signatureRInt = new(big.Int)
		signatureSInt = new(big.Int)
	)

	R, _ := signatureRInt.SetString(signatureRString, 10)
	S, _ := signatureSInt.SetString(signatureSString, 10)
	signatureRInt = R
	signatureSInt = S

	return ecdsa.Verify(&publicKey, messsageByte, signatureRInt, signatureSInt)
}

func verifyASN1() bool {
	return ecdsa.VerifyASN1(&publicKey, messsageByte, signatureByte)
}

func loadPublicKeyFromPem(certificatePem string) {
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
}

func loadPublicKeyFromDer(publicKeyBytes []byte) {
	curve := elliptic.P384()
	publicKey.Curve = curve
	publicKey.X, publicKey.Y = elliptic.Unmarshal(curve, publicKeyBytes)
}

func verifyEidSignature() {
	// loadPublicKeyFromPem(publicKeyPem)
	loadPublicKeyFromDer(publicKeyBytes)

	result := verifyNormally()
	// result := verifyASN1()
	fmt.Println("result     : ", result)
	fmt.Println("public key : ", hex.EncodeToString(elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)))
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

func main() {
	// useMessageRaw()
	useMessageHex()

	verifyEidSignature()
	// testVerifyNIST384P()
}
