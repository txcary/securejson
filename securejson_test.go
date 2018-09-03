package securejson
import (
	"errors"
	"fmt"
)

type StubStorage struct {
	jsonBytes []byte	
}

func (obj *StubStorage) Put(key string, value []byte) (error) {
	obj.jsonBytes = value 
	//fmt.Println("Put", string(obj.jsonBytes))
	return nil
}
	
func (obj *StubStorage) Get(key string) ([]byte, error) {
	if len(obj.jsonBytes)==0 {
		return []byte{}, errors.New("Empty")
	}
	//fmt.Println("Get", string(obj.jsonBytes))
	return obj.jsonBytes, nil	
}


func ExampleNew() {
	storage := new(StubStorage)
	obj := New(storage)	
	jsonBytes, err := obj.GenerateJson("MyUser", "1234", "MyData")
	if err != nil {
		panic(err)
	}
	ok, err := obj.VerifyJson(jsonBytes)
	if err != nil || !ok {
		fmt.Println("Verify the Generated Json Fail")
	}
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
		fmt.Println(err)
		fmt.Println("Get Json Fail")
	}
	ok, err = obj.VerifyJson(jsonBytes)
	if err != nil {
		fmt.Println("Verify Json Fail")
	}
	fmt.Println(ok)
	//output:
	//true
}