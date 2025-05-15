package ctaptypes

import "github.com/google/uuid"

type (
	Version           string
	Versions          []Version
	PinUvAuthProtocol uint
)

const (
	FIDO_2_0     Version = "FIDO_2_0"
	FIDO_2_1_PRE Version = "FIDO_2_1_PRE"
	FIDO_2_1     Version = "FIDO_2_1"
	FIDO_2_2     Version = "FIDO_2_2"
	U2F_V2       Version = "U2F_V2"
)

const (
	PinUvAuthProtocolOne PinUvAuthProtocol = iota + 1
	PinUvAuthProtocolTwo
)

type AuthenticatorGetInfoResponse struct {
	Versions                         Versions                        `cbor:"1,keyasint"`
	Extensions                       []string                        `cbor:"2,keyasint"`
	AAGUID                           uuid.UUID                       `cbor:"3,keyasint"`
	Options                          map[Option]bool                 `cbor:"4,keyasint"`
	MaxMsgSize                       uint                            `cbor:"5,keyasint"`
	PinUvAuthProtocols               []PinUvAuthProtocol             `cbor:"6,keyasint"`
	MaxCredentialCountInList         uint                            `cbor:"7,keyasint"`
	MaxCredentialLength              uint                            `cbor:"8,keyasint"`
	Transports                       []string                        `cbor:"9,keyasint"`
	Algorithms                       []PublicKeyCredentialParameters `cbor:"10,keyasint"`
	MaxSerializedLargeBlobArray      uint                            `cbor:"11,keyasint"`
	ForcePinChange                   bool                            `cbor:"12,keyasint"`
	MinPinLength                     uint                            `cbor:"13,keyasint"`
	FirmwareVersion                  uint                            `cbor:"14,keyasint"`
	MaxCredBlobLength                uint                            `cbor:"15,keyasint"`
	MaxRPIDsForSetMinPINLength       uint                            `cbor:"16,keyasint"`
	PreferredPlatformUvAttempts      uint                            `cbor:"17,keyasint"`
	UvModality                       uint                            `cbor:"18,keyasint"`
	Certifications                   map[string]uint64               `cbor:"19,keyasint"`
	RemainingDiscoverableCredentials uint                            `cbor:"20,keyasint"`
	VendorPrototypeConfigCommands    []uint                          `cbor:"21,keyasint"`
	AttestationFormats               []string                        `cbor:"22,keyasint"`
	UvCountSinceLastPinEntry         uint                            `cbor:"23,keyasint"`
	LongTouchForReset                bool                            `cbor:"24,keyasint"`
	EncIdentifier                    string                          `cbor:"25,keyasint"`
	TransportsForReset               []string                        `cbor:"26,keyasint"`
	PinComplexityPolicy              bool                            `cbor:"27,keyasint"`
	PinComplexityPolicyURL           string                          `cbor:"28,keyasint"`
	MaxPINLength                     uint                            `cbor:"29,keyasint"`
}
