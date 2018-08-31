package securejson

import (
	"encoding/json"
)

type Storage interface {
	PutJson(inputJson []byte) (error)
	GetJson(inputJson []byte) ([]byte, error)
}

type SecureJson struct {
	storageStrategy Storage
}

type Json struct {
	UserName string
	Signature string
	EncryptedData string
	Timestamp string
	PublicKey string
}

func (obj *SecureJson) genHash(userData []byte, encryptedData []byte, timeData []byte, pubkeyData []byte) (fullHash []byte) {
	userHash,_ := obj.hash(userData)
	dataHash,_ := obj.hash(encryptedData)	
	timeHash,_ := obj.hash(timeData[:8])
	pubkeyHash,_ := obj.hash(pubkeyData[:65])	
	
	full := make([]byte, 32*4)
	copy(full[:32], userHash)
	copy(full[32:64], pubkeyHash)
	copy(full[64:96], timeHash)
	copy(full[96:128], dataHash)
	fullHash,_ = obj.hash(full[:128])
	return
}

func (obj *SecureJson) GenerateJson(user string, passwd string, data string) (outputJson []byte, err error) {
	privKey,_ := obj.hash([]byte(passwd))	

	userData := []byte(user)
	encryptedData,_ := obj.encrypt(data, privKey)
	timeData,_ := obj.getTimestamp()
	pubkeyData,_ := obj.getPubKey(privKey)

	fullHash := obj.genHash(userData, encryptedData, timeData, pubkeyData)
	sigData,_ := obj.sign(fullHash, privKey) 
	
	var jsonMap Json
	jsonMap.UserName = user
	jsonMap.Signature = obj.bytesToString(sigData) 
	jsonMap.EncryptedData = obj.bytesToString(encryptedData) 
	jsonMap.Timestamp = obj.bytesToString(timeData)
	jsonMap.PublicKey = obj.bytesToString(pubkeyData)

	outputJson, err = json.Marshal(jsonMap)
	return
}

func (obj *SecureJson) VerifyJson(jsonBytes []byte) (ok bool) {
	var jsonMap Json
	err := json.Unmarshal(jsonBytes, &jsonMap)
	if err != nil {
		return false
	}	

	if !obj.checkTimestamp(jsonMap.Timestamp) {
		return false
	}
	
	userData := []byte(jsonMap.UserName)
	encryptedData := obj.stringToBytes(jsonMap.EncryptedData)
	timeData := obj.stringToBytes(jsonMap.Timestamp)
	pubkeyData := obj.stringToBytes(jsonMap.PublicKey)
	sigData := obj.stringToBytes(jsonMap.Signature)
	fullHash := obj.genHash(userData, encryptedData, timeData, pubkeyData)

	return obj.verify(fullHash, pubkeyData, sigData)
}

func (obj *SecureJson) PutJson(inputJson []byte) (err error) {
	err = obj.storageStrategy.PutJson(inputJson)
	return
}

func (obj *SecureJson) GetJson(inputJson []byte) (outputJson []byte, err error) {
	outputJson, err = obj.storageStrategy.GetJson(inputJson)
	return
}

func New(storageObj Storage) *SecureJson {
	obj := new(SecureJson)
	obj.storageStrategy = storageObj
	return obj
}