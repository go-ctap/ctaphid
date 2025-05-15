package ctaphid

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var respPackets = []string{
	`Ri/vTZAAhgamAQICCQOlAQIDOBggASFYIGUwTZr5xmK+EffrDnBoxG3fLYUnqCxMJY++N2PkjG2VIlggGJxNrQ==`,
	`Ri/vTQDlCT2rXnrYQhN0DM0LWCASXti9f+sreUfUi4WEBlgg9LagOl5Yndw64EuM+UAGwRIRo4lJszckFs5EVw==`,
	`Ri/vTQFS7EH2CRYKamtyYXNvdnMua3k=`,
}

func TestNewMessage(t *testing.T) {
	// Write packets into a buffer
	buf := bytes.NewBuffer(nil)
	for _, pStr := range respPackets {
		p, err := base64.StdEncoding.DecodeString(pStr)
		require.NoError(t, err)

		buf.Write(p)
	}

	responseBytes := buf.Bytes()

	// Read a message from it
	m := new(Message)
	_, err := m.ReadFrom(buf)
	require.NoError(t, err)

	{
		// Write it back to another buffer
		buf := bytes.NewBuffer(nil)
		_, err = m.WriteTo(buf)
		require.NoError(t, err)

		// Add HID paging byte
		writtenBytes := make([]byte, 0)
		chunks := lo.Chunk(buf.Bytes(), 65)
		for _, chunk := range chunks {
			writtenBytes = append(writtenBytes, bytes.TrimLeft(chunk, "\x00")...)
		}

		assert.Equal(t, responseBytes, writtenBytes)
	}
}
