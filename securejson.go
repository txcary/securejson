package securejson

import (
	"encoding/json"
	"errors"
)

type Storage interface {
	Put(key string, value []byte) error
	Get(key string) ([]byte, error)
}

type SecureJson struct {
	storageStrategy Storage
}

type Json struct {
	UserName      string
	Signature     string
	EncryptedData string
	Timestamp     string
	PublicKey     string
	//TODO: NewPublicKey string
}

func (obj *SecureJson) Encrypt(data string, userName string, key []byte) (string, error) {
	iv, _ := obj.hash([]byte(userName))
	cipherBytes, err := obj.encrypt([]byte(data), iv, key)
	return obj.bytesToString(cipherBytes), err
}

func (obj *SecureJson) Decrypt(data string, userName string, key []byte) (string, error) {
	iv, _ := obj.hash([]byte(userName))
	cipherBytes := obj.stringToBytes(data)
	plainBytes, err := obj.encrypt(cipherBytes, iv, key)
	return string(plainBytes), err
}

func (obj *SecureJson) GenerateJson(user string, passwd string, data string) (outputJson []byte, err error) {
	privKey, _ := obj.hash([]byte(passwd))
	iv, _ := obj.hash([]byte(user))

	userBytes := []byte(user)
	encryptedBytes, _ := obj.encrypt([]byte(data), iv, privKey)
	timeBytes, _ := obj.getTimestamp()
	pubkeyBytes, _ := obj.getPubKey(privKey)

	fullHash := obj.genHash(userBytes, encryptedBytes, timeBytes, pubkeyBytes)
	sigBytes, _ := obj.sign(fullHash, privKey)

	var jsonMap Json
	jsonMap.UserName = user
	jsonMap.Signature = obj.bytesToString(sigBytes)
	jsonMap.EncryptedData = obj.bytesToString(encryptedBytes)
	jsonMap.Timestamp = obj.bytesToString(timeBytes)
	jsonMap.PublicKey = obj.bytesToString(pubkeyBytes)

	outputJson, err = json.Marshal(jsonMap)
	return
}

func (obj *SecureJson) VerifyJson(jsonBytes []byte) (ok bool, err error) {
	var jsonMap Json
	err = json.Unmarshal(jsonBytes, &jsonMap)
	if err != nil {
		return false, err
	}

	if !obj.checkTimestampBeforeNow(jsonMap.Timestamp) {
		return false, err
	}

	userData := []byte(jsonMap.UserName)
	encryptedData := obj.stringToBytes(jsonMap.EncryptedData)
	timeData := obj.stringToBytes(jsonMap.Timestamp)
	pubkeyData := obj.stringToBytes(jsonMap.PublicKey)
	sigData := obj.stringToBytes(jsonMap.Signature)
	fullHash := obj.genHash(userData, encryptedData, timeData, pubkeyData)

	ok = obj.verify(fullHash, pubkeyData, sigData)
	if ok {
		return
	} else {
		err = errors.New("Signature verify fail")
		return false, err
	}
}

func (obj *SecureJson) PutJson(inputJson []byte) (err error) {
	var ok bool
	if ok, err = obj.VerifyJson(inputJson); !ok || err != nil {
		return
	}
	outputJson, err := obj.getJsonFromStorage(inputJson)
	if err != nil {
		err = obj.putJsonToStorage(inputJson)
		return
	}
	if ok, err = obj.checkInputOutputJson(inputJson, outputJson); err != nil || !ok {
		return
	}

	err = obj.putJsonToStorage(inputJson)
	return
}

func (obj *SecureJson) GetJson(inputJson []byte) (outputJson []byte, err error) {
	var ok bool
	if ok, err = obj.VerifyJson(inputJson); !ok || err != nil {
		return
	}
	outputJson, err = obj.getJsonFromStorage(inputJson)
	if err != nil {
		return
	}
	if ok, err = obj.checkInputOutputJson(inputJson, outputJson); err != nil || !ok {
		outputJson = []byte{}
		return
	}
	return
}

func New(storageObj Storage) *SecureJson {
	obj := new(SecureJson)
	obj.storageStrategy = storageObj
	return obj
}
