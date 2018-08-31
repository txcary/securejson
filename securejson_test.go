package securejson
import (
	"fmt"
)

type StubStorage struct {
	jsonBytes []byte	
}

func (obj *StubStorage) PutJson(inputJson []byte) (error) {
	obj.jsonBytes = inputJson
	fmt.Println(string(obj.jsonBytes))
	return nil
}
	
func (obj *StubStorage) GetJson(inputJson []byte) ([]byte, error) {
	fmt.Println(string(obj.jsonBytes))
	return []byte("{}"), nil	
}


func ExampleNew() {
	storage := new(StubStorage)
	obj := New(storage)	
	jsonBytes, err := obj.GenerateJson("MyUser", "1234", "MyData")
	if err != nil {
		panic(err)
	}
	//obj.PutJson(jsonBytes)
	//obj.GetJson(jsonBytes)
	ok := obj.VerifyJson(jsonBytes)
	fmt.Println(ok)
	//output:
	//true
}