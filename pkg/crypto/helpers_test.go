package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var origDataForCompress = []byte("hello world! hello world! hello world!")

func TestCompressDecompress(t *testing.T) {
	compressed, err := compress(origDataForCompress)
	require.NoError(t, err)

	decompressed, err := decompress(compressed)
	require.NoError(t, err)

	assert.Equal(t, origDataForCompress, decompressed)
}
