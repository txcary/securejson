package securejson

import (
	"encoding/json"
	"errors"
	"fmt"
)

type StubStorage struct {
	jsonBytes []byte
}

func (obj *StubStorage) Put(key string, value []byte) error {
	obj.jsonBytes = value
	//fmt.Println("Put", string(obj.jsonBytes))
	return nil
}

func (obj *StubStorage) Get(key string) ([]byte, error) {
	if len(obj.jsonBytes) == 0 {
		return []byte{}, errors.New("Empty")
	}
	//fmt.Println("Get", string(obj.jsonBytes))
	return obj.jsonBytes, nil
}

func testJson(jsonBytes []byte, logprifix string, obj *SecureJson) {
	ok, err := obj.VerifyJson(jsonBytes)
	if err != nil || !ok {
		fmt.Println(err)
		fmt.Println(logprifix, "Verify the Json Fail")
	}
	var data Json
	err = json.Unmarshal(jsonBytes, &data)
	if err != nil {
		fmt.Println(logprifix, "Json Unmarshal Fail")
	}
	passwd, _ := obj.hash([]byte("1234"))
	plain, err := obj.Decrypt(data.EncryptedData, data.UserName, passwd)
	if err != nil {
		fmt.Println(logprifix, "Decrypt Fail")
	}
	if string(plain) != "MyData" {
		fmt.Println(logprifix, "Decrypted data Fail")
	}
}

func ExampleNew() {
	storage := new(StubStorage)
	obj := New(storage)
	jsonBytes := []byte(`{"UserName":"MyUser","Signature":"MEUCIDJmafX+XGJV+Ws2jz0lF2YdJLcrEXAw1ZBPB0/+KjJyAiEA1CR3f/pbngSl0P0mqb7McKSbveSsQ1ir5L4ulpKamuw=","EncryptedData":"F4Zw1vYy","Timestamp":"W5D07g==","PublicKey":"BCNhwc+1nmUYLSDJnacQaKQB1YyT26gdwHCZZd1iwsB14rfGvwv9fuAHjyln9Alap2Voxp/rrdiU2QvE8HuMt5s="}`)
	testJson(jsonBytes, "Hardcoded", obj)

	jsonBytes, err := obj.GenerateJson("MyUser", "1234", "MyData")
	if err != nil {
		panic(err)
	}
	testJson(jsonBytes, "Generated", obj)
	
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
	testJson(jsonBytes, "Get", obj)
	fmt.Println(true)
	//output:
	//true
}
