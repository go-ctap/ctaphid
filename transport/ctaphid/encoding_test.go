package ctaphid

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
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

func TestNewMessageFramesSpecPayloadBoundaries(t *testing.T) {
	// CTAP 2.3 PS, 11.2.4: with 64-byte packets, init packets carry
	// 57 bytes, continuation packets carry 59 bytes, and max payload is 7609.
	cid := ChannelID{1, 2, 3, 4}

	for _, tc := range []struct {
		name        string
		payloadLen  int
		packetCount int
	}{
		{name: "empty", payloadLen: 0, packetCount: 1},
		{name: "fills init packet", payloadLen: initPacketDataSize, packetCount: 1},
		{name: "requires first continuation", payloadLen: initPacketDataSize + 1, packetCount: 2},
		{name: "maximum payload", payloadLen: 7609, packetCount: 129},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xaa}, tc.payloadLen)
			msg, err := NewMessage(cid, CTAPHID_PING, payload)
			require.NoError(t, err)
			require.Len(t, msg, tc.packetCount)

			buf := bytes.NewBuffer(nil)
			n, err := msg.WriteTo(buf)
			require.NoError(t, err)
			require.Equal(t, int64(tc.packetCount*hidReportPacketSize), n)

			written := buf.Bytes()
			require.Len(t, written, tc.packetCount*hidReportPacketSize)

			for packetIndex := range tc.packetCount {
				chunk := written[packetIndex*hidReportPacketSize : (packetIndex+1)*hidReportPacketSize]
				assert.Equal(t, byte(0), chunk[0], "report ID")

				raw := chunk[1:]
				assert.Equal(t, cid[:], raw[:4], "CID")

				if packetIndex == 0 {
					assert.Equal(t, byte(CTAPHID_PING)|INIT_PACKET_BIT, raw[4], "init command byte")
					assert.Equal(t, uint16(tc.payloadLen), binary.BigEndian.Uint16(raw[5:7]), "BCNT")

					dataLen := min(tc.payloadLen, initPacketDataSize)
					assert.Equal(t, payload[:dataLen], raw[initPacketHeaderSize:initPacketHeaderSize+dataLen])
					assert.Equal(t, make([]byte, initPacketDataSize-dataLen), raw[initPacketHeaderSize+dataLen:])
					continue
				}

				sequence := packetIndex - 1
				assert.Equal(t, byte(sequence), raw[4], "continuation sequence")

				offset := initPacketDataSize + sequence*continuationPacketDataSize
				dataLen := min(tc.payloadLen-offset, continuationPacketDataSize)
				assert.Equal(t, payload[offset:offset+dataLen], raw[continuationPacketHeaderSize:continuationPacketHeaderSize+dataLen])
				assert.Equal(t, make([]byte, continuationPacketDataSize-dataLen), raw[continuationPacketHeaderSize+dataLen:])
			}
		})
	}
}

func TestNewMessageRejectsPayloadAboveSpecMaximum(t *testing.T) {
	_, err := NewMessage(ChannelID{1, 2, 3, 4}, CTAPHID_PING, bytes.Repeat([]byte{0xaa}, 7610))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMessageTooLarge))
}
