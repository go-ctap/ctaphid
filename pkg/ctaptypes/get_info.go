package ctaptypes

import (
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/google/uuid"
)

type (
	Version           string
	Versions          []Version
	PinUvAuthProtocol uint
)

const (
	FIDO_2_0     Version = "FIDO_2_0"
	FIDO_2_1_PRE Version = "FIDO_2_1_PRE"
	FIDO_2_1     Version = "FIDO_2_1"
	FIDO_2_3     Version = "FIDO_2_3"
	U2F_V2       Version = "U2F_V2"
)

const (
	PinUvAuthProtocolOne PinUvAuthProtocol = iota + 1
	PinUvAuthProtocolTwo
)

const (
	DefaultMaxMsgSize       uint = 1024
	DefaultMinPINCodePoints uint = 4
)

// AuthenticatorGetInfoResponse is used in Metadata Statement specification as well, so json notation added.
type AuthenticatorGetInfoResponse struct {
	Versions                         Versions                                      `cbor:"1,keyasint" json:"versions"`
	Extensions                       []webauthntypes.ExtensionIdentifier           `cbor:"2,keyasint" json:"extensions"`
	AAGUID                           uuid.UUID                                     `cbor:"3,keyasint" json:"aaguid"`
	Options                          map[Option]bool                               `cbor:"4,keyasint" json:"options"`
	MaxMsgSize                       *uint                                         `cbor:"5,keyasint" json:"maxMsgSize"`
	PinUvAuthProtocols               []PinUvAuthProtocol                           `cbor:"6,keyasint" json:"pinUvAuthProtocols"`
	MaxCredentialCountInList         *uint                                         `cbor:"7,keyasint" json:"maxCredentialCountInList"`
	MaxCredentialIDLength            *uint                                         `cbor:"8,keyasint" json:"maxCredentialIdLength"`
	Transports                       []string                                      `cbor:"9,keyasint" json:"transports"`
	Algorithms                       []webauthntypes.PublicKeyCredentialParameters `cbor:"10,keyasint" json:"algorithms"`
	MaxSerializedLargeBlobArray      *uint                                         `cbor:"11,keyasint" json:"maxSerializedLargeBlobArray"`
	ForcePINChange                   *bool                                         `cbor:"12,keyasint" json:"forcePINChange"`
	MinPINLength                     *uint                                         `cbor:"13,keyasint" json:"minPINLength"`
	FirmwareVersion                  *uint                                         `cbor:"14,keyasint" json:"firmwareVersion"`
	MaxCredBlobLength                *uint                                         `cbor:"15,keyasint" json:"maxCredBlobLength"`
	MaxRPIDsForSetMinPINLength       *uint                                         `cbor:"16,keyasint" json:"maxRPIDsForSetMinPINLength"`
	PreferredPlatformUvAttempts      *uint                                         `cbor:"17,keyasint" json:"preferredPlatformUvAttempts"`
	UvModality                       *uint                                         `cbor:"18,keyasint" json:"uvModality"`
	Certifications                   map[string]uint64                             `cbor:"19,keyasint" json:"certifications"`
	RemainingDiscoverableCredentials *uint                                         `cbor:"20,keyasint" json:"remainingDiscoverableCredentials"`
	VendorPrototypeConfigCommands    []uint                                        `cbor:"21,keyasint" json:"vendorPrototypeConfigCommands"`
	AttestationFormats               []string                                      `cbor:"22,keyasint" json:"attestationFormats"`
	UvCountSinceLastPinEntry         *uint                                         `cbor:"23,keyasint" json:"uvCountSinceLastPinEntry"`
	LongTouchForReset                *bool                                         `cbor:"24,keyasint" json:"longTouchForReset"`
	EncIdentifier                    *string                                       `cbor:"25,keyasint" json:"encIdentifier"`
	TransportsForReset               []string                                      `cbor:"26,keyasint" json:"transportsForReset"`
	PinComplexityPolicy              *bool                                         `cbor:"27,keyasint" json:"pinComplexityPolicy"`
	PinComplexityPolicyURL           *string                                       `cbor:"28,keyasint" json:"pinComplexityPolicyURL"`
	MaxPINLength                     *uint                                         `cbor:"29,keyasint" json:"maxPINLength"`
	EncCredStoreState                *string                                       `cbor:"30,keyasint" json:"encCredStoreState"`
	AuthenticatorConfigCommands      []uint                                        `cbor:"31,keyasint" json:"authenticatorConfigCommands"`
}

func (r *AuthenticatorGetInfoResponse) EffectiveMaxMsgSize() uint {
	if r != nil && r.MaxMsgSize != nil {
		return *r.MaxMsgSize
	}

	return DefaultMaxMsgSize
}

func (r *AuthenticatorGetInfoResponse) EffectiveMinPINLength() uint {
	if r != nil && r.MinPINLength != nil && *r.MinPINLength > DefaultMinPINCodePoints {
		return *r.MinPINLength
	}

	return DefaultMinPINCodePoints
}

func (r *AuthenticatorGetInfoResponse) MaxCredBlobLengthValue() (uint, bool) {
	if r == nil || r.MaxCredBlobLength == nil {
		return 0, false
	}

	return *r.MaxCredBlobLength, true
}

func (r *AuthenticatorGetInfoResponse) MaxSerializedLargeBlobArrayValue() (uint, bool) {
	if r == nil || r.MaxSerializedLargeBlobArray == nil {
		return 0, false
	}

	return *r.MaxSerializedLargeBlobArray, true
}
