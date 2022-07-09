package securejson

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"git.tcp.direct/kayos/common/entropy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"golang.org/x/crypto/sha3"
)

func (obj *SecureJSON) encrypt(plainText []byte, iv []byte, key []byte) ([]byte, error) {
	if len(iv) < aes.BlockSize {
		return []byte{}, errors.New("iv size error")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return []byte{}, err
	}
	cipherText := make([]byte, len(plainText))
	// iv := make([]byte, aes.BlockSize)

	stream := cipher.NewCTR(block, iv[:aes.BlockSize])
	stream.XORKeyStream(cipherText, plainText)
	return cipherText, err
}

func (obj *SecureJSON) genHash(userBytes []byte, encryptedBytes []byte, timeBytes []byte, pubkeyBytes []byte) (fullHash []byte) {
	userHash, _ := obj.hash(userBytes)
	dataHash, _ := obj.hash(encryptedBytes)
	timeHash, _ := obj.hash(timeBytes)
	pubkeyHash, _ := obj.hash(pubkeyBytes[:65])

	full := make([]byte, 32*4)
	copy(full[:32], userHash)
	copy(full[32:64], pubkeyHash)
	copy(full[64:96], timeHash)
	copy(full[96:128], dataHash)
	fullHash, _ = obj.hash(full[:128])
	return
}

func (obj *SecureJSON) checkInputOutputJSON(inputJSON []byte, outputJSON []byte) (ok bool, err error) {
	ok = false
	var ji JSON
	err = json.Unmarshal(inputJSON, &ji)
	if err != nil {
		return
	}
	var jo JSON
	err = json.Unmarshal(outputJSON, &jo)
	if err != nil {
		return
	}

	if ji.UserName != jo.UserName {
		err = errors.New("Check fail for UserName. " + ji.UserName + "!=" + jo.UserName)
		return
	}
	if ji.PublicKey != jo.PublicKey {
		err = errors.New("check failed for PublicKey")
		return
	}
	if obj.convertFromStringToInt64(ji.Timestamp) < obj.convertFromStringToInt64(jo.Timestamp) {
		err = errors.New("input timestamp must be greater then the ouput one")
		return
	}
	ok = true
	return
}

func (obj *SecureJSON) getUserNameFromJSON(inputJSON []byte) (userName string, err error) {
	var jsonStruct JSON
	userName = ""
	err = json.Unmarshal(inputJSON, &jsonStruct)
	if err == nil {
		userName = jsonStruct.UserName
	}
	return
}

func (obj *SecureJSON) getJSONFromStorage(inputJSON []byte) (outputJSON []byte, err error) {
	userName, err := obj.getUserNameFromJSON(inputJSON)
	if err == nil {
		outputJSON, err = obj.storageStrategy.Get(userName)
	}
	return
}

func (obj *SecureJSON) putJSONToStorage(inputJSON []byte) (err error) {
	userName, err := obj.getUserNameFromJSON(inputJSON)
	if err == nil {
		err = obj.storageStrategy.Put(userName, inputJSON)
	}
	return
}

func (obj *SecureJSON) convertFromStringToInt64(timeStr string) (timestamp int64) {
	_, _ = fmt.Sscanf(timeStr, "%x", &timestamp)
	return
}

func (obj *SecureJSON) checkTimestampBeforeNow(timeStr string) (ok bool) {
	timestamp := obj.convertFromStringToInt64(timeStr)
	timenow := time.Now().UnixNano()
	return timenow > timestamp
}

func (obj *SecureJSON) bytesToString(msg []byte) string {
	return base64.StdEncoding.EncodeToString(msg)
}

func (obj *SecureJSON) stringToBytes(msg string) (res []byte) {
	var err error
	res, err = base64.StdEncoding.DecodeString(msg)
	if err != nil {
		panic(err)
	}
	return
}

func (obj *SecureJSON) verify(msg []byte, pub []byte, sig []byte) bool {
	pubKey, err := btcec.ParsePubKey(pub)
	if err != nil {
		return false
	}
	signature, err := ecdsa.ParseSignature(sig)
	if err != nil {
		return false
	}
	return signature.Verify(msg, pubKey)
}

func (obj *SecureJSON) sign(msg []byte, privKey []byte) ([]byte, error) {
	priv, _ := btcec.PrivKeyFromBytes(privKey)
	sig, err := priv.ToECDSA().Sign(entropy.GetOptimizedRand(), msg, nil)
	if err != nil {
		return []byte{}, err
	}
	return sig, err
}

func (obj *SecureJSON) getPubKey(privKey []byte) ([]byte, error) {
	pubKey := make([]byte, 65)
	_, pub := btcec.PrivKeyFromBytes(privKey)
	pubKey = pub.SerializeUncompressed()
	return pubKey, nil
}

func (obj *SecureJSON) getTimestamp() ([]byte, error) {
	timeNowBytes := make([]byte, 8)
	timeNowStr := fmt.Sprintf("%x", time.Now().Unix())
	timeNowBytes, err := hex.DecodeString(timeNowStr)
	return timeNowBytes, err
}

func (obj *SecureJSON) shake256(data []byte, length int) ([]byte, error) {
	sum := make([]byte, length)
	hashObj := sha3.NewShake256()
	_, writeErr := hashObj.Write(data)
	if writeErr != nil {
		return sum, writeErr
	}
	_, readErr := hashObj.Read(sum)
	return sum, readErr
}

func (obj *SecureJSON) hash(data []byte) ([]byte, error) {
	return obj.shake256(data, 32)
}

func (obj *SecureJSON) genIv(userName string) ([]byte, error) {
	return obj.shake256([]byte(userName), 16)
}
