package ctaphid

import (
	"bytes"
	"encoding/base64"
	"testing"

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
	responsePackets := make([][]byte, 0, len(respPackets))
	for _, pStr := range respPackets {
		p, err := base64.StdEncoding.DecodeString(pStr)
		require.NoError(t, err)

		padded := make([]byte, hidPacketSize)
		copy(padded, p)
		responsePackets = append(responsePackets, padded)
		buf.Write(padded)
	}

	// Read a message from it
	m := new(Message)
	_, err := m.ReadFrom(buf)
	require.NoError(t, err)

	{
		// Write it back to another buffer
		buf := bytes.NewBuffer(nil)
		_, err = m.WriteTo(buf)
		require.NoError(t, err)

		writtenBytes := buf.Bytes()
		require.Len(t, writtenBytes, len(responsePackets)*hidReportPacketSize)

		for i, expectedPacket := range responsePackets {
			chunk := writtenBytes[i*hidReportPacketSize : (i+1)*hidReportPacketSize]
			assert.Equal(t, byte(0), chunk[0])
			assert.Equal(t, expectedPacket, chunk[1:])
		}
	}
}
