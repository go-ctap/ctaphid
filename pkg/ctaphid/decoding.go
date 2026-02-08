package ctaphid

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

func (m *Message) ReadFrom(device io.Reader) (int64, error) {
	buf := bufio.NewReaderSize(device, 64)
	var bytesRead int

	total := -1
	for total != 0 {
		var p packet

		cid := make([]byte, 4)
		cidCnt, err := io.ReadFull(buf, cid)
		if err != nil {
			return 0, err
		}
		bytesRead += cidCnt
		p.cid = ChannelID(cid)

		cmdOrSeq, err := buf.ReadByte()
		if err != nil {
			return 0, err
		}
		cmdOrSeqCnt := 1
		bytesRead += cmdOrSeqCnt

		if (cmdOrSeq & INIT_PACKET_BIT) != 0 {
			p.command = Command(cmdOrSeq & ^INIT_PACKET_BIT)
		} else {
			p.sequence = cmdOrSeq
			p.continuation = true
		}

		dataLenCnt := 0
		if !p.continuation {
			dataLen := make([]byte, 2)
			cnt, err := io.ReadFull(buf, dataLen)
			if err != nil {
				return 0, err
			}
			bytesRead += cnt
			p.length = binary.BigEndian.Uint16(dataLen)
			total = int(p.length)
			dataLenCnt = cnt
		} else if total < 0 {
			return 0, errors.New("continuation packet before init packet")
		}

		dataCnt := total
		if total > 64-(cidCnt+cmdOrSeqCnt+dataLenCnt) {
			dataCnt = 64 - (cidCnt + cmdOrSeqCnt + dataLenCnt)
		}

		p.data = make([]byte, dataCnt)
		dataCnt, err = io.ReadFull(buf, p.data)
		if err != nil {
			return 0, err
		}
		bytesRead += dataCnt

		total -= dataCnt
		*m = append(*m, &p)
	}

	return int64(bytesRead), nil
}
