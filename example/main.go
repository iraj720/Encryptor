package main

import (
	"encryptor"
	"fmt"
)

type encryptorExample struct {
}

func (ee *encryptorExample) Decrypt(src string) (string, error) {
	return fmt.Sprintf("%s decrypted", src), nil
}
func (ee *encryptorExample) DecryptWithId(src string, userId string) (string, error) {
	return fmt.Sprintf("%s decryptedWithId", src), nil
}
func (ee *encryptorExample) Encrypt(src string) (string, error) {
	return fmt.Sprintf("%s encrypted", src), nil
}
func (ee *encryptorExample) EncryptWithId(src string, userId string) (string, error) {
	return fmt.Sprintf("%s encryptedWithId", src), nil
}
func (ee *encryptorExample) GetCiphertext(userId string) (string, error) {
	return fmt.Sprintf("cipher of %s", userId), nil
}

type example struct {
	Id     int
	Name   string
	Family string
	Number string
}

func main() {
	es := encryptor.NewEncryptionService(&encryptorExample{})
	exampl := example{
		Id:     1,
		Name:   "nima",
		Family: "family",
	}
	res, err := es.EncryptStruct(exampl)
	if err != nil {
		panic(err)
	}
	fmt.Println(res.(*example))
}
