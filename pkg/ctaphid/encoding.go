package ctaphid

import (
	"bufio"
	"encoding/binary"
	"io"

	"github.com/samber/lo"
)

// NewMessage creates a new message.
func NewMessage(cid ChannelID, cmd Command, data []byte) (Message, error) {
	if len(data) > 7609 {
		return nil, ErrMessageTooLarge
	}

	msg := make(Message, 0)
	msg = append(msg, &packet{
		cid:     cid,
		command: cmd,
		length:  uint16(len(data)),
		// DATA starts from offset 7
		data: lo.Slice(data, 0, 64-7),
	})

	// if data is longer than 64 bytes minus offset, split it into chunks and
	// append them to the message as continuation packets
	if len(data) > (64 - 7) {
		chunks := lo.Chunk[byte](data[64-7:], 64-5)
		for i, chunk := range chunks {
			msg = append(msg, &packet{
				cid:          cid,
				sequence:     byte(i),
				data:         chunk,
				continuation: true,
			})
		}
	}

	return msg, nil
}

// WriteTo writes the message to the device.
func (m Message) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for _, p := range m {
		// We cannot write directly to the device because every writing should be a single packet.
		buf := bufio.NewWriterSize(w, 65)

		// Report ID in our case is always 0.
		if err := buf.WriteByte(0x00); err != nil {
			return 0, err
		}
		total += 1

		// Packet itself.
		n, err := p.WriteTo(buf)
		if err != nil {
			return 0, err
		}
		total += n

		// Flush the buffer to the device.
		if err := buf.Flush(); err != nil {
			return 0, err
		}
	}

	return total, nil
}

// WriteTo writes the packet to the writer e.g., a buffer.
func (p *packet) WriteTo(w io.Writer) (int64, error) {
	// CID: offset 0; length 4
	cidCnt, err := w.Write(p.cid[:])
	if err != nil {
		return 0, err
	}

	// CMD or SEQ: offset 4; length 1
	cmdOrSeqCnt := 0
	if !p.continuation {
		cmdCnt, err := w.Write([]byte{byte(p.command) | INIT_PACKET_BIT})
		if err != nil {
			return 0, err
		}
		cmdOrSeqCnt = cmdCnt
	} else {
		seqCnt, err := w.Write([]byte{p.sequence})
		if err != nil {
			return 0, err
		}
		cmdOrSeqCnt = seqCnt
	}

	// BCNTH and BCNTL: offset 5; length 2
	// Only present in an init packet.
	dataLenCnt := 0
	if !p.continuation {
		dataLen := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLen, p.length)
		cnt, err := w.Write(dataLen)
		if err != nil {
			return 0, err
		}
		dataLenCnt = cnt
	}

	// DATA:
	//   Init packet offset 7; length 57
	//   Continuation packet offset 5; length 59
	dataCnt, err := w.Write(p.data)
	if err != nil {
		return 0, err
	}

	return int64(cidCnt + cmdOrSeqCnt + dataLenCnt + dataCnt), nil
}
