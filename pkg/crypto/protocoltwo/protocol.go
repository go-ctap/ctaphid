package protocoltwo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/hkdf"
)

func KDF(z []byte) ([]byte, error) {
	// Zero bytes for salt
	salt := make([]byte, 32)

	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(
		hkdf.New(sha256.New, z, salt, []byte("CTAP2 HMAC key")),
		hmacKey,
	); err != nil {
		return nil, fmt.Errorf("calculating CTAP2 HMAC key using HKDF failed: %w", err)
	}

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(
		hkdf.New(sha256.New, z, salt, []byte("CTAP2 AES key")),
		aesKey,
	); err != nil {
		return nil, fmt.Errorf("calculating CTAP2 AES key using HKDF failed: %w", err)
	}

	return slices.Concat(hmacKey, aesKey), nil
}

func Encrypt(sharedSecret []byte, demPlaintext []byte) ([]byte, error) {
	if len(sharedSecret) != 64 {
		return nil, fmt.Errorf("invalid shared secret length")
	}
	if len(demPlaintext)%16 != 0 {
		return nil, fmt.Errorf("invalid plaintext length")
	}

	// Discard the first 32 bytes of the key.
	// (This selects the AES-key portion of the shared secret.)
	key := sharedSecret[32:]

	// Encrypt PIN using AES-CBC using random IV
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES cipher: %w", err)
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("cannot generate random iv: %w", err)
	}
	ciphertext := make([]byte, len(demPlaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, demPlaintext)

	return slices.Concat(iv, ciphertext), nil
}

func Decrypt(sharedSecret []byte, demCiphertext []byte) ([]byte, error) {
	// Discard the first 32 bytes of the key.
	// (This selects the AES-key portion of the shared secret.)
	key := sharedSecret[32:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create new AES cipher: %w", err)
	}

	if len(demCiphertext) < block.BlockSize() {
		return nil, errors.New("invalid ciphertext")
	}

	plaintext := make([]byte, 32)
	iv := demCiphertext[:16]
	ciphertext := demCiphertext[16:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

func Authenticate(sharedSecret []byte, message []byte) []byte {
	// If the key is longer than 32 bytes, discard the excess.
	// (This selects the HMAC-key portion of the shared secret.
	// When the key is the pinUvAuthToken, it is exactly 32 bytes long, and thus this step has no effect.)
	key := sharedSecret[:32]

	hasher := hmac.New(sha256.New, key)
	hasher.Write(message)
	return hasher.Sum(nil)
}
