package securejson

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/sha3"
	"time"
)

func (obj *SecureJson) encrypt(plainText []byte, iv []byte, key []byte) ([]byte, error) {
	if len(iv) < aes.BlockSize {
		return []byte{}, errors.New("iv size error")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return []byte{}, err
	}
	cipherText := make([]byte, len(plainText))
	//iv := make([]byte, aes.BlockSize)

	stream := cipher.NewCTR(block, iv[:aes.BlockSize])
	stream.XORKeyStream(cipherText, plainText)
	return cipherText, err
}

func (obj *SecureJson) genHash(userBytes []byte, encryptedBytes []byte, timeBytes []byte, pubkeyBytes []byte) (fullHash []byte) {
	userHash, _ := obj.hash(userBytes)
	dataHash, _ := obj.hash(encryptedBytes)
	timeHash, _ := obj.hash(timeBytes[:4])
	pubkeyHash, _ := obj.hash(pubkeyBytes[:65])

	full := make([]byte, 32*4)
	copy(full[:32], userHash)
	copy(full[32:64], pubkeyHash)
	copy(full[64:96], timeHash)
	copy(full[96:128], dataHash)
	fullHash, _ = obj.hash(full[:128])
	return
}

func (obj *SecureJson) checkInputOutputJson(inputJson []byte, outputJson []byte) (ok bool, err error) {
	ok = false
	var ji Json
	err = json.Unmarshal(inputJson, &ji)
	if err != nil {
		return
	}
	var jo Json
	err = json.Unmarshal(outputJson, &jo)
	if err != nil {
		return
	}

	if ji.UserName != jo.UserName {
		err = errors.New("Check fail for UserName. " + ji.UserName + "!=" + jo.UserName)
		return
	}
	if ji.PublicKey != jo.PublicKey {
		err = errors.New("Check fail for PublicKey")
		return
	}
	if obj.convertFromStringToInt64(ji.Timestamp) < obj.convertFromStringToInt64(jo.Timestamp) {
		err = errors.New("Check fail for Timestamp. Input timestamp must be greater then the ouput one.")
		return
	}
	ok = true
	return
}

func (obj *SecureJson) getUserNameFromJson(inputJson []byte) (userName string, err error) {
	var jsonStruct Json
	userName = ""
	err = json.Unmarshal(inputJson, &jsonStruct)
	if err == nil {
		userName = jsonStruct.UserName
	}
	return
}

func (obj *SecureJson) getJsonFromStorage(inputJson []byte) (outputJson []byte, err error) {
	userName, err := obj.getUserNameFromJson(inputJson)
	if err == nil {
		outputJson, err = obj.storageStrategy.Get(userName)
	}
	return
}

func (obj *SecureJson) putJsonToStorage(inputJson []byte) (err error) {
	userName, err := obj.getUserNameFromJson(inputJson)
	if err == nil {
		err = obj.storageStrategy.Put(userName, inputJson)
	}
	return
}

func (obj *SecureJson) convertFromStringToInt64(timeStr string) (timestamp int64) {
	fmt.Sscanf(timeStr, "%x", &timestamp)
	return
}

func (obj *SecureJson) checkTimestampBeforeNow(timeStr string) (ok bool) {
	timestamp := obj.convertFromStringToInt64(timeStr)
	timenow := time.Now().UnixNano()
	return (timenow > timestamp)
}

func (obj *SecureJson) bytesToString(msg []byte) string {
	return base64.StdEncoding.EncodeToString(msg)
}

func (obj *SecureJson) stringToBytes(msg string) (res []byte) {
	var err error
	res, err = base64.StdEncoding.DecodeString(msg)
	if err != nil {
		panic(err)
	}
	return
}

func (obj *SecureJson) verify(msg []byte, pub []byte, sig []byte) bool {
	pubKey, err := btcec.ParsePubKey(pub, btcec.S256())
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
	timeNowStr := fmt.Sprintf("%x", time.Now().Unix())
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
