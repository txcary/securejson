package securejson

import (
	"encoding/json"
	"errors"
	"fmt"
)

type Storage interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
}

type SecureJSON struct {
	storageStrategy Storage
}

type Payload struct {
	UserName      string
	Signature     string
	EncryptedData string
	Timestamp     string
	PublicKey     string
	// TODO: NewPublicKey string
}

func (obj *SecureJSON) Encrypt(data string, userName string, key []byte) (string, error) {
	iv, _ := obj.genIv(userName)
	cipherBytes, err := obj.encrypt([]byte(data), iv, key)
	return obj.bytesToString(cipherBytes), err
}

func (obj *SecureJSON) Decrypt(data string, userName string, key []byte) (string, error) {
	iv, _ := obj.hash([]byte(userName))
	cipherBytes := obj.stringToBytes(data)
	plainBytes, err := obj.encrypt(cipherBytes, iv, key)
	return string(plainBytes), err
}

func (obj *SecureJSON) GenerateJSON(user string, passwd string, data string) (outputJSON []byte, err error) {
	privKey, _ := obj.hash([]byte(passwd))
	iv, _ := obj.hash([]byte(user))

	userBytes := []byte(user)
	encryptedBytes, _ := obj.encrypt([]byte(data), iv, privKey)
	timeBytes, _ := obj.getTimestamp()
	pubkeyBytes, _ := obj.getPubKey(privKey)

	fullHash := obj.genHash(userBytes, encryptedBytes, timeBytes, pubkeyBytes)
	sigBytes, _ := obj.sign(fullHash, privKey)

	var jsonMap Payload
	jsonMap.UserName = user
	jsonMap.Signature = obj.bytesToString(sigBytes)
	jsonMap.EncryptedData = obj.bytesToString(encryptedBytes)
	jsonMap.Timestamp = obj.bytesToString(timeBytes)
	jsonMap.PublicKey = obj.bytesToString(pubkeyBytes)

	outputJSON, err = json.Marshal(jsonMap)
	return
}

func (obj *SecureJSON) VerifyJSON(jsonBytes []byte) (ok bool, err error) {
	var jsonMap Payload
	err = json.Unmarshal(jsonBytes, &jsonMap)
	if err != nil {
		return false, fmt.Errorf("json.Unmarshal failure during verification: %x", err)
	}
	if jsonMap.UserName == "" || jsonMap.Signature == "" ||
		jsonMap.EncryptedData == "" || jsonMap.Timestamp == "" || jsonMap.PublicKey == "" {
		return false, errors.New("json.Unmarshal failure during verification: missing fields")
	}

	if !obj.checkTimestampBeforeNow(jsonMap.Timestamp) {
		err = errors.New("timestamp check failed")
		return false, err
	}

	userBytes := []byte(jsonMap.UserName)
	encryptedBytes := obj.stringToBytes(jsonMap.EncryptedData)
	timeBytes := obj.stringToBytes(jsonMap.Timestamp)
	pubkeyBytes := obj.stringToBytes(jsonMap.PublicKey)
	sigBytes := obj.stringToBytes(jsonMap.Signature)
	fullHash := obj.genHash(userBytes, encryptedBytes, timeBytes, pubkeyBytes)

	ok = obj.verify(fullHash, pubkeyBytes, sigBytes)
	if ok {
		return
	} else {
		err = errors.New("signature verify failed")
		return false, err
	}
}

func (obj *SecureJSON) PutJSON(inputJSON []byte) (err error) {
	var ok bool
	if ok, err = obj.VerifyJSON(inputJSON); !ok || err != nil {
		return
	}
	outputJSON, err := obj.getJSONFromStorage(inputJSON)
	if err != nil {
		err = obj.putJSONToStorage(inputJSON)
		return
	}
	if ok, err = obj.checkInputOutputJSON(inputJSON, outputJSON); err != nil || !ok {
		return
	}

	err = obj.putJSONToStorage(inputJSON)
	return
}

func (obj *SecureJSON) getJSON(inputJSON []byte) (outputJSON []byte, err error) {
	var ok bool
	if ok, err = obj.VerifyJSON(inputJSON); !ok || err != nil {
		return
	}
	outputJSON, err = obj.getJSONFromStorage(inputJSON)
	if err != nil {
		return
	}
	if ok, err = obj.checkInputOutputJSON(inputJSON, outputJSON); err != nil || !ok {
		outputJSON = []byte{}
		return
	}
	return
}

func New(storageObj Storage) *SecureJSON {
	obj := new(SecureJSON)
	obj.storageStrategy = storageObj
	return obj
}
