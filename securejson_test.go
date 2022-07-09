package securejson

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

type StubStorage struct {
	jsonBytes []byte
}

func (obj *StubStorage) Put(key string, value []byte) error {
	obj.jsonBytes = value
	fmt.Println("Put", string(obj.jsonBytes))
	return nil
}

func (obj *StubStorage) Get(key string) ([]byte, error) {
	if len(obj.jsonBytes) == 0 {
		return []byte{}, errors.New("Empty")
	}
	fmt.Println("Get", string(obj.jsonBytes))
	return obj.jsonBytes, nil
}

func testJson(jsonBytes []byte, logPrefix string, obj *SecureJson, t *testing.T) {
	ok, err := obj.VerifyJson(jsonBytes)
	if err != nil || !ok {
		t.Errorf("%s: VerifyJson failed: %s", logPrefix, err)
	}
	var data Json
	err = json.Unmarshal(jsonBytes, &data)
	if err != nil {
		t.Errorf("%s: Unmarshal failed: %s", logPrefix, err)
	}
	passwd, _ := obj.hash([]byte("1234"))
	plain, err := obj.Decrypt(data.EncryptedData, data.UserName, passwd)
	if err != nil {
		t.Errorf("%s: Decrypt failed: %s", logPrefix, err)
	}
	if plain != "MyData" {
		t.Errorf("%s: Decrypt failed: %s", logPrefix, err)
	}
}

func TestNew(t *testing.T) {
	storage := new(StubStorage)
	obj := New(storage)
	jsonBytes := []byte(`{"UserName":"MyUser","Signature":"MEUCIDJmafX+XGJV+Ws2jz0lF2YdJLcrEXAw1ZBPB0/+KjJyAiEA1CR3f/pbngSl0P0mqb7McKSbveSsQ1ir5L4ulpKamuw=","EncryptedData":"F4Zw1vYy","Timestamp":"W5D07g==","PublicKey":"BCNhwc+1nmUYLSDJnacQaKQB1YyT26gdwHCZZd1iwsB14rfGvwv9fuAHjyln9Alap2Voxp/rrdiU2QvE8HuMt5s="}`)
	testJson(jsonBytes, "Hardcoded", obj, t)

	jsonBytes, err := obj.GenerateJson("MyUser", "1234", "MyData")
	if err != nil {
		panic(err)
	}
	testJson(jsonBytes, "Generated", obj, t)

	_, err = obj.GetJson(jsonBytes)
	if err == nil {
		fmt.Println("Expecting error when no value stored")
	}
	err = obj.PutJson(jsonBytes)
	if err != nil {
		fmt.Println("Put Json fail")
	}
	_, err = obj.GetJson(jsonBytes)
	if err != nil {
		fmt.Println("Get Json Fail")
	}
	testJson(jsonBytes, "Get", obj, t)
	fmt.Println(true)
	// output:
	// true
}
