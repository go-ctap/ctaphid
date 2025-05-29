package protocolone

import (
	"encoding/base64"
	"math/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	derivedSecret             = "iGCxsjN/EAIMuVwL2bvpKnuIB/+eJT84b+sAvyD80zI="
	messageAuthenticationCode = "mCElssa3wFoz1+hjKAG/jg=="
)

func TestKDF(t *testing.T) {
	// Create derived with zero material
	key1 := KDF(nil)

	// Create a deterministic shared secret
	sharedSecret := make([]byte, 32)
	r := rand.New(rand.NewSource(0))
	_, err := r.Read(sharedSecret)
	require.NoError(t, err)

	// Create derived with a shared secret
	key2 := KDF(sharedSecret)

	// Ensure key1 and key2 are different
	assert.NotEqual(t, key1, key2)

	// Compare it with reference
	savedKey, _ := base64.StdEncoding.DecodeString(derivedSecret)
	assert.Equal(t, key2, savedKey)
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(derivedSecret)
	badKey := append(key, 0)

	padding := make([]byte, 16)
	plaintext := []byte("16-byte block...")
	badPlaintext := []byte("17-byte block...!")

	// Encrypt with a 65-byte key
	_, err := Encrypt(badKey, plaintext)
	assert.Error(t, err)

	// Encrypt with a 17-byte block
	_, err = Encrypt(key, badPlaintext)
	assert.Error(t, err)

	// Test encrypt-decrypt with padding
	{
		ciphertext, err := Encrypt(key, plaintext)
		require.NoError(t, err)

		decrypted, err := Decrypt(key, ciphertext)
		assert.Equal(t, slices.Concat(plaintext, padding), decrypted)
	}

	// Test encrypt-decrypt without padding
	{
		ciphertext, err := Encrypt(key, slices.Concat(plaintext, plaintext))
		require.NoError(t, err)

		decrypted, err := Decrypt(key, ciphertext)
		assert.Equal(t, slices.Concat(plaintext, plaintext), decrypted)
	}
}

func TestAuthenticate(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(derivedSecret)
	message := []byte("hello world!")

	mac := Authenticate(key, message)
	assert.Equal(t, 16, len(mac))
	assert.Equal(t, messageAuthenticationCode, base64.StdEncoding.EncodeToString(mac))
}
