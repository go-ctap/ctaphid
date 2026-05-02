package ctaptypes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseGetAssertionAuthDataRejectsShortData(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		make([]byte, 36),
	} {
		_, err := ParseGetAssertionAuthData(data)
		require.Error(t, err)
	}
}

func TestParseMakeCredentialAuthDataRejectsTruncatedAttestedCredentialData(t *testing.T) {
	data := make([]byte, 37)
	data[32] = byte(AuthDataFlagAttestedCredentialDataIncluded)

	_, err := ParseMakeCredentialAuthData(data)
	require.Error(t, err)

	data = append(data, make([]byte, 16)...)
	_, err = ParseMakeCredentialAuthData(data)
	require.Error(t, err)

	data = append(data, 0, 2, 0x01)
	_, err = ParseMakeCredentialAuthData(data)
	require.Error(t, err)
}
