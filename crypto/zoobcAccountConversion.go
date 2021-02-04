package main

import (
	"encoding/hex"

	"github.com/zoobc/zoobc-core/common/signaturetype"
)

func main() {
	a := &signaturetype.Ed25519Signature{}
	publickey, _ := a.GetPublicKeyFromEncodedAddress("ZBC_2GLMFQ4Q_V5VW4ABQ_FX6PRD73_B4JKWZAY_MNCN2GKB_ZPTU2YLF_I2ORO25T")
	println(hex.EncodeToString(publickey))
}
