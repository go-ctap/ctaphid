package protocolone

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func KDF(z []byte) []byte {
	hasher := sha256.New()
	hasher.Write(z)
	return hasher.Sum(nil)
}

func Encrypt(sharedSecret []byte, demPlaintext []byte) ([]byte, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("invalid shared secret length")
	}
	if len(demPlaintext)%16 != 0 {
		return nil, fmt.Errorf("invalid plaintext length")
	}

	// Encrypt PIN using AES-CBC using null IV
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES cipher: %w", err)
	}

	iv := make([]byte, block.BlockSize())
	ciphertext := make([]byte, len(demPlaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, demPlaintext)

	return ciphertext, nil
}

func Decrypt(sharedSecret []byte, demCiphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES cipher: %w", err)
	}

	iv := make([]byte, block.BlockSize())
	plaintext := make([]byte, 32)

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, demCiphertext)

	return plaintext, nil
}

func Authenticate(sharedSecret []byte, message []byte) []byte {
	hasher := hmac.New(sha256.New, sharedSecret)
	hasher.Write(message)
	return hasher.Sum(nil)[:16]
}
