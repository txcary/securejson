package securejson

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"git.tcp.direct/kayos/common/entropy"
)

type StubStorage struct {
	jsonBytes []byte
	t         *testing.T
}

func (obj *StubStorage) Put(key string, value []byte) error {
	if value == nil || len(value) == 0 {
		return errors.New("nil value")
	}
	obj.jsonBytes = value
	obj.t.Log("Put: ", string(obj.jsonBytes))
	return nil
}

func (obj *StubStorage) Get(key string) ([]byte, error) {
	if len(obj.jsonBytes) == 0 {
		return []byte{}, errors.New("empty")
	}
	obj.t.Log("Get: ", string(obj.jsonBytes))
	return obj.jsonBytes, nil
}

func validate(jsonBytes []byte, obj *SecureJSON) (data *Payload, err error) {
	var ok bool
	ok, err = obj.VerifyJSON(jsonBytes)
	if err != nil || !ok {
		return nil, fmt.Errorf("failed to validate Payload: %s", err)
	}
	if err = json.Unmarshal(jsonBytes, &data); err != nil {
		err = fmt.Errorf("failed to unmarshal: %s", err)
	}
	return
}

func testJSON(t *testing.T, jsonBytes []byte, logPrefix string, obj *SecureJSON) {
	data, err := validate(jsonBytes, obj)
	if err != nil {
		t.Errorf("[%s]: %s", logPrefix, err)
	}
	passwd, _ := obj.hash([]byte("1234"))
	plain, err := obj.Decrypt(data.EncryptedData, data.UserName, passwd)
	if err != nil {
		t.Errorf("%s: Decrypt failed: %s", logPrefix, err)
	}
	if plain != "MyData" {
		t.Errorf("%s: Decrypt failed, wanted %v, but got %v", logPrefix, "MyData", plain)
	}
}

func TestNew(t *testing.T) {
	storage := new(StubStorage)
	storage.t = t
	obj := New(storage)
	jsonBytes := []byte(`{"UserName":"MyUser","Signature":"MEUCIDJmafX+XGJV+Ws2jz0lF2YdJLcrEXAw1ZBPB0/+KjJyAiEA1CR3f/pbngSl0P0mqb7McKSbveSsQ1ir5L4ulpKamuw=","EncryptedData":"F4Zw1vYy","Timestamp":"W5D07g==","PublicKey":"BCNhwc+1nmUYLSDJnacQaKQB1YyT26gdwHCZZd1iwsB14rfGvwv9fuAHjyln9Alap2Voxp/rrdiU2QvE8HuMt5s="}`)
	testJSON(t, jsonBytes, "Hardcoded", obj)

	jsonBytes, err := obj.GenerateJSON("MyUser", "1234", "MyData")
	if err != nil {
		panic(err)
	}
	testJSON(t, jsonBytes, "Generated", obj)

	t.Log("trying to get a value before it's stored...")
	_, err = obj.getJSON(jsonBytes)
	if err == nil {
		t.Errorf("Expecting error when no value stored")
	}
	t.Log("trying to store a value...")
	err = obj.PutJSON(jsonBytes)
	if err != nil {
		t.Errorf("Put Payload failed: %s", err)
	}
	t.Log("trying to get the stored value...")
	_, err = obj.getJSON(jsonBytes)
	if err != nil {
		t.Errorf("Get Payload failed: %x", err)
	}
	testJSON(t, jsonBytes, "Get", obj)
}

func TestEntropic(t *testing.T) {
	storage := new(StubStorage)
	storage.t = t
	for i := 0; i < 100; i++ {
		err := entropyTest(storage)
		if err != nil {
			t.Fatalf("entropyTest failed: %s", err)
		}
	}
}

func entropyTest(storage *StubStorage) error {
	sjsonFactory := New(storage)
	user := entropy.RandStr(10)
	pass := entropy.RandStr(25)
	hashed, err := sjsonFactory.hash([]byte(pass))
	if err != nil {
		return err
	}
	data := entropy.RandStr(100)
	jsonBytes, err := sjsonFactory.GenerateJSON(user, pass, data)
	if err != nil {
		return err
	}
	validCiphertext, err := validate(jsonBytes, sjsonFactory)
	if err != nil {
		return err
	}
	plaintext, err := sjsonFactory.Decrypt(validCiphertext.EncryptedData, user, hashed)
	if err != nil {
		return err
	}
	if plaintext != data {
		return fmt.Errorf("plaintext != data\n%v != %v", plaintext, data)
	}
	return nil
}
