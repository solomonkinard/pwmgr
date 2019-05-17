package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encryptFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encrypt(data, passphrase))
}

func decryptFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	return decrypt(data, passphrase)
}

func cwd() string {
	return filepath.Dir(os.Args[0])
}

func encryptAndDecryptFile() {
	path := cwd()
	filename := path + "/sample.txt"
	println(filename)
	encryptFile(filename, []byte("Hello World"), "password1")
	fmt.Println(string(decryptFile(filename, "password1")))
}

func encryptVolatile(password []byte) {
	ciphertext := encrypt([]byte("Hello World"), string(password))
	fmt.Printf("Encrypted: %x\n", ciphertext)
	plaintext := decrypt(ciphertext, string(password))
	fmt.Printf("Decrypted: %s\n", plaintext)
}

func createFile(filename string, data string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write([]byte(data))
}

func main() {
	path := cwd()
	password_path := path + "/password.txt"
	decrypted_path := path + "/decrypted.txt"
	encrypted_path := path + "/encrypted.txt"
	// createFile(password_path, "tmp password")
	// createFile(decrypted_path, "tmp data")
	password, err := ioutil.ReadFile(password_path)
	if err != nil {
		panic(err.Error())
	}
	if len(os.Args) < 2 {
		println("missing: -e: encrypt, -d: decrypt")
		return
	}
	if os.Args[1] == "-e" {
		decrypted, err := ioutil.ReadFile(decrypted_path)
		if err != nil {
			panic(err.Error())
		}
		encryptFile(encrypted_path, decrypted, string(password))
	} else {
		encrypted, err := ioutil.ReadFile(encrypted_path)
		if err != nil {
			panic(err.Error())
		}
		createFile(decrypted_path, string(decrypt(encrypted, string(password))))
	}
}
