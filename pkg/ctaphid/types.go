package ctaphid

// Message is a sequence of packets.
type Message []*packet

// packet represents CTAP packet.
type packet struct {
	cid          ChannelID
	command      Command
	sequence     byte
	length       uint16
	data         []byte
	continuation bool
}

// ChannelID represents CTAP channel ID.
type ChannelID [4]byte

// BROADCAST_CID represents CTAP broadcast channel ID.
var BROADCAST_CID = ChannelID{0xff, 0xff, 0xff, 0xff}

// CBORResponse represents CTAPHID_CBOR (0x10) command response.
// https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#usb-hid-cbor
type CBORResponse struct {
	StatusCode StatusCode
	Data       []byte
}

// InitResponse represents CTAPHID_INIT (0x06) command response.
// https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#usb-hid-init
type InitResponse struct {
	Nonce                            []byte
	CID                              ChannelID
	CTAPHIDProtocolVersionIdentifier byte
	MajorDeviceVersion               byte
	MinorDeviceVersion               byte
	BuildDeviceVersion               byte
	CapabilityFlags                  byte
}

func (r *InitResponse) ImplementsWink() bool {
	return r.CapabilityFlags&byte(CAPABILITY_WINK) != 0
}

func (r *InitResponse) ImplementsCBOR() bool {
	return r.CapabilityFlags&byte(CAPABILITY_CBOR) != 0
}

func (r *InitResponse) NotImplementsMSG() bool {
	return r.CapabilityFlags&byte(CAPABILITY_NMSG) != 0
}

// PingResponse represents CTAPHID_PING command response.
// https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#usb-hid-ping
type PingResponse struct {
	Bytes []byte
}

// ErrorResponse represents CTAPHID_ERROR (0x3F) command response.
type ErrorResponse struct {
	ErrorCode Error
}
