package encryptor

import (
	"encoding/json"
	"fmt"
	"reflect"
)

type EncryptionService interface {
	// for string
	Encryptor
	// encryption-needed-data should be string so first convert everything to string and fill your model
	// then pass it here
	EncryptStruct(model interface{}) (interface{}, error)
	// encryption-needed-data should be string so first convert everything to string and fill your model
	// then pass it here
	EncryptStructWithId(Iuuid string, model interface{}) (interface{}, error)
	DecryptStruct(model interface{}) (interface{}, error)
	DecryptStructWithId(Iuuid string, model interface{}) (interface{}, error)
}

type Encryptor interface {
	Decrypt(data string) (string, error)
	DecryptWithId(input string, userId string) (string, error)
	Encrypt(src string) (string, error)
	EncryptWithId(src string, userId string) (string, error)
	GetCiphertext(userId string) (string, error)
}

type encryptionService struct {
	Encryptor
}

type tagHelperValueIsEncrypted string

const (
	tagHelperEncryptionKey                                     = "encryption"
	tagHelperKeyEncryptionValue_True tagHelperValueIsEncrypted = "true"
)

func NewEncryptionService(enc Encryptor) EncryptionService {
	return &encryptionService{Encryptor: enc}
}

func (br *encryptionService) EncryptStructWithId(Iuuid string, model interface{}) (interface{}, error) {

	// if its string
	val, ok := model.(string)
	if ok {
		encryptedVal, err := br.Encryptor.EncryptWithId(val, Iuuid)
		if err != nil {
			return nil, err
		}
		return encryptedVal, nil
	}

	// struct
	v := reflect.ValueOf(model)
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("not a struct or string")
	}

	values := make(map[string]interface{}, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		values[v.Type().Field(i).Name] = v.Field(i).Interface()
	}
	for i, v := range values {
		src := ""
		switch v.(type) {
		case string:
			src = v.(string)
		}
		if src == "" {
			continue
		}

		encryptedVal, err := br.Encryptor.EncryptWithId(src, Iuuid)
		if err != nil {
			return nil, err
		}
		values[i] = encryptedVal
	}

	jsonStr, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	t := reflect.ValueOf(model)
	res := reflect.New(t.Type()).Interface()
	// Convert struct
	if err := json.Unmarshal(jsonStr, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// just works on strings
func (br *encryptionService) EncryptStruct(model interface{}) (interface{}, error) {

	// if its string
	val, ok := model.(string)
	if ok {
		encryptedVal, err := br.Encryptor.Encrypt(val)
		if err != nil {
			return nil, err
		}
		return encryptedVal, nil
	}

	// struct
	v := reflect.ValueOf(model)
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("not a struct or string")
	}
	
	values := make(map[string]interface{}, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		values[v.Type().Field(i).Name] = v.Field(i).Interface()
	}
	for i, v := range values {
		src := ""
		switch v.(type) {
		case string:
			src = v.(string)
		}
		if src == "" {
			continue
		}

		encryptedVal, err := br.Encryptor.Encrypt(src)
		if err != nil {
			return nil, err
		}
		values[i] = encryptedVal
	}
	jsonStr, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	t := reflect.ValueOf(model)
	res := reflect.New(t.Type()).Interface()
	// Convert struct
	
	if err := json.Unmarshal(jsonStr, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (br *encryptionService) DecryptStructWithId(Iuuid string, model interface{}) (interface{}, error) {

	// if its string
	val, ok := model.(string)
	if ok {
		encryptedVal, err := br.Encryptor.DecryptWithId(val, Iuuid)
		if err != nil {
			return nil, err
		}
		model = encryptedVal
		return encryptedVal, nil
	}

	// struct
	v := reflect.ValueOf(model)
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("not a struct or string")
	}

	values := make(map[string]interface{}, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		values[v.Type().Field(i).Name] = v.Field(i).Interface()
	}
	for i, v := range values {
		src := ""
		switch v.(type) {
		case string:
			src = v.(string)
		}
		if src == "" {
			continue
		}

		encryptedVal, err := br.Encryptor.DecryptWithId(src, Iuuid)
		if err != nil {
			return nil, err
		}
		values[i] = encryptedVal
	}
	jsonStr, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	t := reflect.ValueOf(model)
	res := reflect.New(t.Type()).Interface()
	// Convert struct
	if err := json.Unmarshal(jsonStr, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// just works on strings
func (br *encryptionService) DecryptStruct(model interface{}) (interface{}, error) {

	// if its string
	val, ok := model.(string)
	if ok {
		encryptedVal, err := br.Encryptor.Decrypt(val)
		if err != nil {
			return nil, err
		}
		return encryptedVal, nil
	}

	// struct
	v := reflect.ValueOf(model)
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("not a struct or string")
	}

	values := make(map[string]interface{}, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		values[v.Type().Field(i).Name] = v.Field(i).Interface()
	}
	for i, v := range values {
		src := ""
		switch v.(type) {
		case string:
			src = v.(string)
		}
		if src == "" {
			continue
		}

		encryptedVal, err := br.Encryptor.Decrypt(src)
		if err != nil {
			return nil, err
		}
		values[i] = encryptedVal
	}
	jsonStr, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	t := reflect.ValueOf(model)
	res := reflect.New(t.Type()).Interface()
	// Convert struct
	if err := json.Unmarshal(jsonStr, &res); err != nil {
		return nil, err
	}
	return res, nil
}
