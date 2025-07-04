package ctaphid

import (
	"crypto/subtle"
	"errors"
	"io"
	"slices"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
)

func CBOR(dev io.ReadWriter, cid ChannelID, data []byte) (*CBORResponse, error) {
	msg, err := NewMessage(cid, CTAPHID_CBOR, data)
	if err != nil {
		return nil, err
	}

	if _, err := msg.WriteTo(dev); err != nil {
		return nil, err
	}

read:
	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(dev); err != nil {
			return nil, err
		}

		if len(respMsg) < 1 {
			return nil, ErrInvalidResponseMessage
		}

		var respData []byte
		for i, p := range respMsg {
			if i == 0 {
				switch p.command {
				case CTAPHID_CBOR:
					command := ctaptypes.Command(data[0])
					code := StatusCode(p.data[0])
					if code != CTAP2_OK {
						return nil, newCTAPError(command, code)
					}
				case CTAPHID_ERROR:
					return nil, errors.New(Error(p.data[0]).String())
				case CTAPHID_KEEPALIVE:
					continue read
				default:
					return nil, ErrUnexpectedCommand
				}
			}

			respData = slices.Concat(respData, p.data)
		}

		r := &CBORResponse{
			StatusCode: StatusCode(respData[0]),
			Data:       respData[1:],
		}

		return r, nil
	}
}

func Init(dev io.ReadWriter, cid ChannelID, nonce []byte) (*InitResponse, error) {
	msg, err := NewMessage(cid, CTAPHID_INIT, nonce)
	if err != nil {
		return nil, err
	}

	if _, err := msg.WriteTo(dev); err != nil {
		return nil, err
	}

	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(dev); err != nil {
			return nil, err
		}

		if len(respMsg) < 1 {
			return nil, ErrInvalidResponseMessage
		}

		p := respMsg[0]

		switch p.command {
		case CTAPHID_INIT:
			if subtle.ConstantTimeCompare(p.data[:8], nonce) != 1 {
				return nil, errors.New("invalid nonce")
			}

			r := &InitResponse{
				Nonce:                            p.data[:8],
				CID:                              ChannelID(p.data[8 : 8+4]),
				CTAPHIDProtocolVersionIdentifier: p.data[12],
				MajorDeviceVersion:               p.data[13],
				MinorDeviceVersion:               p.data[14],
				BuildDeviceVersion:               p.data[15],
				CapabilityFlags:                  p.data[16],
			}

			return r, nil
		case CTAPHID_ERROR:
			return nil, errors.New(Error(p.data[0]).String())
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return nil, ErrUnexpectedCommand
		}
	}
}

func Ping(dev io.ReadWriter, cid ChannelID, ping []byte) (*PingResponse, error) {
	msg, err := NewMessage(cid, CTAPHID_PING, ping)
	if err != nil {
		return nil, err
	}

	if _, err := msg.WriteTo(dev); err != nil {
		return nil, err
	}

read:
	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(dev); err != nil {
			return nil, err
		}

		if len(respMsg) < 1 {
			return nil, ErrInvalidResponseMessage
		}

		var pong []byte
		for i, p := range respMsg {
			if i == 0 {
				switch p.command {
				case CTAPHID_PING:
				case CTAPHID_ERROR:
					return nil, errors.New(Error(p.data[0]).String())
				case CTAPHID_KEEPALIVE:
					continue read
				default:
					return nil, ErrUnexpectedCommand
				}
			}

			pong = slices.Concat(pong, p.data)
		}

		r := &PingResponse{
			Bytes: pong,
		}

		return r, nil
	}
}

func Cancel(dev io.ReadWriter, cid ChannelID) error {
	msg, err := NewMessage(cid, CTAPHID_CANCEL, nil)
	if err != nil {
		return err
	}

	if _, err := msg.WriteTo(dev); err != nil {
		return err
	}

	return nil
}

func Wink(dev io.ReadWriter, cid ChannelID) error {
	msg, err := NewMessage(cid, CTAPHID_WINK, nil)
	if err != nil {
		return err
	}

	if _, err := msg.WriteTo(dev); err != nil {
		return err
	}

	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(dev); err != nil {
			return err
		}

		if len(respMsg) < 1 {
			return ErrInvalidResponseMessage
		}

		p := respMsg[0]

		switch p.command {
		case CTAPHID_WINK:
			return nil
		case CTAPHID_ERROR:
			return errors.New(Error(p.data[0]).String())
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return ErrUnexpectedCommand
		}
	}
}

func Lock(dev io.ReadWriter, cid ChannelID, seconds uint8) error {
	msg, err := NewMessage(cid, CTAPHID_LOCK, []byte{seconds})
	if err != nil {
		return err
	}

	if _, err := msg.WriteTo(dev); err != nil {
		return err
	}

	for {
		respMsg := make(Message, 0)
		if _, err := respMsg.ReadFrom(dev); err != nil {
			return err
		}

		if len(respMsg) < 1 {
			return ErrInvalidResponseMessage
		}

		p := respMsg[0]

		switch p.command {
		case CTAPHID_LOCK:
			return nil
		case CTAPHID_ERROR:
			return errors.New(Error(p.data[0]).String())
		case CTAPHID_KEEPALIVE:
			continue
		default:
			return ErrUnexpectedCommand
		}
	}
}
