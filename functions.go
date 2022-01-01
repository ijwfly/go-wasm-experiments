package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"github.com/vugu/vugu"
)

func (c *Root) InputText(event vugu.DOMEvent) {
	c.inputText = event.JSEvent().Get("target").Get("value").String()
}

func (c *Root) InputPassword(event vugu.DOMEvent) {
	c.inputPassword = event.JSEvent().Get("target").Get("value").String()
}

func (c *Root) Encrypt() {
	encryptedResult, _ := c.EncryptData(c.inputText, c.inputPassword)
	b64encoded := base64.StdEncoding.EncodeToString(encryptedResult)

	c.ShowText = c.inputText
	c.ShowResult = b64encoded
	c.ShowKey = c.inputPassword
}

func (c *Root) Decrypt() {
	b64decoded, err := base64.StdEncoding.DecodeString(c.inputText)
	if err != nil {
		panic("b64 decoding error")
	}
	decryptedResult, _ := c.DecryptData(b64decoded, c.inputPassword)

	c.ShowText = c.inputText
	c.ShowResult = string(decryptedResult)
	c.ShowKey = c.inputPassword
}

func (c *Root) EncryptData(toEncrypt string, encryptionKey string) ([]byte, error) {
	toEncryptBytes := []byte(toEncrypt)

	key := sha256.Sum256([]byte(encryptionKey))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	nonce := key[:12]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Seal(nil, nonce, toEncryptBytes, nil), nil
}

func (c *Root) DecryptData(toDecrypt []byte, encryptionKey string) ([]byte, error) {
	key := sha256.Sum256([]byte(encryptionKey))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	nonce := key[:12]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, toDecrypt, nil)
}
