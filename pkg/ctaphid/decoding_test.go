package ctaphid

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	getInfoResponseDump = "y2QaNpABawCyAYRmVTJGX1YyaEZJRE9fMl8waEZJRE9fMl8xbEZJRE9fMl8xX1BSRQKFaGNyZWRCbG9ia2NyZctkGjYAZFByb3RlY3RraG1hYy1zZWNyZXRsbGFyZ2VCbG9iS2V5bG1pblBpbkxlbmd0aANQ6rtGzOJBgL+unpbLZBo2AfptKXXPBKxicmv1YnVw9WRwbGF09GhhbHdheXNVdvRoY3JlZE1nbXT1aWF1dGhuckNmZ/VpY2xpZW50y2QaNgJQaW71amxhcmdlQmxvYnP1bnBpblV2QXV0aFRva2Vu9W9zZXRNaW5QSU5MZW5ndGj1cG1ha2VDcmVkVctkGjYDdk5vdFJxZPV1Y3JlZGVudGlhbE1nbXRQcmV2aWV39QUZCAAGggIBBwgIGGAJgmN1c2JjbmZjCoKiY2HLZBo2BGxnJmR0eXBlanB1YmxpYy1rZXmiY2FsZydkdHlwZWpwdWJsaWMta2V5CxkIAAz0DQYOGQEADxggEAYTy2QaNgWhZEZJRE8DFBkBFgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

func TestMessage_ReadFrom(t *testing.T) {
	m := new(Message)

	resp, _ := base64.StdEncoding.DecodeString(getInfoResponseDump)
	device := bytes.NewReader(resp)

	n, err := m.ReadFrom(device)
	require.NoError(t, err)

	// ReadFrom reads by 64-bytes blocks, at the end zeros will be presented
	assert.Equal(t, int64(len(bytes.Trim(resp, "\x00"))), n)
}
