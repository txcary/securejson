package securejson
import(
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"time"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/sha3"
)

func (obj *SecureJson) checkTimestamp(timeStr string) (ok bool) {
	var timestamp int64
	fmt.Sscanf(timeStr, "%x", &timestamp) 
	timenow := time.Now().UnixNano()
	return (timenow>timestamp)
}

func (obj *SecureJson) bytesToString(msg []byte) string {
	return hex.EncodeToString(msg)
}

func (obj *SecureJson) stringToBytes(msg string) (res []byte) {
	var err error 
	res, err = hex.DecodeString(msg)
	if err != nil {
		panic(err)
	}
	return
}

func (obj *SecureJson) verify(msg []byte, pub []byte, sig []byte) (bool) {
	pubKey , err := btcec.ParsePubKey(pub, btcec.S256())
	if err != nil {
		return false
	}
	signature, err := btcec.ParseSignature(sig, btcec.S256())
	if err != nil {
		return false
	}
	return signature.Verify(msg, pubKey)
}

func (obj *SecureJson) sign(msg []byte, privKey []byte) ([]byte, error) {
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKey)
	sig, err := priv.Sign(msg)
	if err != nil {
		return []byte{}, err
	}
	return sig.Serialize(), err
}

func (obj *SecureJson) getPubKey(privKey []byte) ([]byte, error) {
	pubKey := make([]byte, 65)
	_, pub := btcec.PrivKeyFromBytes(btcec.S256(), privKey)
	pubKey = pub.SerializeUncompressed()
	return pubKey, nil
}

func (obj *SecureJson) getTimestamp() ([]byte, error) {
	timeNowBytes := make([]byte, 8)
	timeNowStr := fmt.Sprintf("%x", time.Now().UnixNano())
	timeNowBytes, err := hex.DecodeString(timeNowStr)
	return timeNowBytes, err
}

func (obj *SecureJson) hash(data []byte) ([]byte, error) {
	sum := make([]byte, 32)
	hashObj := sha3.NewShake256()
	hashObj.Write(data)
	hashObj.Read(sum)
	return sum, nil
}

func (obj *SecureJson) encrypt(data string, key []byte) ([]byte, error) {
	plainText := []byte(data)
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return []byte{}, err
	}
	cipherText := make([]byte, len(plainText))
	iv := make([]byte, aes.BlockSize)
	
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText, plainText)
	return cipherText, err
}


func (obj *SecureJson) decrypt(data string, key []byte) ([]byte, error) {
	out, err := obj.encrypt(data, key)
	return out, err
}