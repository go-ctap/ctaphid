package crypto

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var origData = []byte("hello world!")

func TestEncryptDecryptLargeBlob(t *testing.T) {
	encKey := make([]byte, 32)
	r := rand.New(rand.NewSource(42))
	_, err := r.Read(encKey)
	require.NoError(t, err)

	encryptedBlob, err := EncryptLargeBlob(encKey, origData)
	require.NoError(t, err)

	decryptedOrigData, err := DecryptLargeBlob(encKey, encryptedBlob)
	require.NoError(t, err)

	assert.Equal(t, decryptedOrigData, origData)
}
