package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

func main() {
	fileName := flag.String("name", "foo", "Name of file to save key to")
	flag.Parse()

	savePrivateFileTo := "./" + *fileName + "-key"
	savePublicFileTo := "./" + *fileName + "-key.pub"

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	privateKeyRes, err := exportRsaPrivateKeyAsPemStrFile(privateKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	publicKey := privateKey.PublicKey

	publicKeyBytes, err := exportRsaPublicKeyAsPemStrFile(&publicKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	publicKeyRes := validateKey(string(publicKeyBytes), "-", "END", "KEY", "BEGIN", "PUBLIC", "\n", " ")

	err = writeKeyToFile(privateKeyRes, savePrivateFileTo)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = writeKeyToFile([]byte(publicKeyRes), savePublicFileTo)
	if err != nil {
		log.Fatal(err.Error())
	}
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}

func exportRsaPrivateKeyAsPemStrFile(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privateKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)

	return privateKeyPem, nil
}

func exportRsaPublicKeyAsPemStrFile(pubKey *rsa.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)

	if err != nil {
		return nil, err
	}
	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)

	return pubKeyPem, nil
}

func validateKey(old string, s ...string) string {

	var yes string
	var res string

	for _, i2 := range s {
		yes = strings.ReplaceAll(old, i2, "")
		old = yes
		res = old
	}
	return res
}
