package securejson

import (
	"fmt"
	"encoding/hex"
)

func dumpBytes(prifix string, bytes []byte) {
	hexString := hex.EncodeToString(bytes)
	fmt.Println(prifix, hexString)
}