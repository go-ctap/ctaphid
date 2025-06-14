package ctaptypes

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
	"github.com/savely-krasovsky/go-ctaphid/pkg/webauthntypes"
)

type AuthenticatorGetAssertionRequest struct {
	RPID              string                                        `cbor:"1,keyasint"`
	ClientDataHash    []byte                                        `cbor:"2,keyasint"`
	AllowList         []webauthntypes.PublicKeyCredentialDescriptor `cbor:"3,keyasint,omitempty"`
	Extensions        *GetExtensionInputs                           `cbor:"4,keyasint,omitempty"`
	Options           map[Option]bool                               `cbor:"5,keyasint,omitempty"`
	PinUvAuthParam    []byte                                        `cbor:"6,keyasint,omitempty"`
	PinUvAuthProtocol PinUvAuthProtocol                             `cbor:"7,keyasint,omitempty"`
}

type AuthenticatorGetAssertionResponse struct {
	Credential               webauthntypes.PublicKeyCredentialDescriptor             `cbor:"1,keyasint"`
	AuthDataRaw              []byte                                                  `cbor:"2,keyasint"`
	AuthData                 *GetAssertionAuthData                                   `cbor:"-"`
	Signature                []byte                                                  `cbor:"3,keyasint"`
	User                     *webauthntypes.PublicKeyCredentialUserEntity            `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials      uint                                                    `cbor:"5,keyasint,omitempty"`
	UserSelected             bool                                                    `cbor:"6,keyasint,omitempty"`
	LargeBlobKey             []byte                                                  `cbor:"7,keyasint,omitempty"`
	UnsignedExtensionOutputs map[webauthntypes.ExtensionIdentifier]any               `cbor:"8,keyasint,omitempty"`
	ExtensionOutputs         *webauthntypes.GetAuthenticationExtensionsClientOutputs `cbor:"-"`
}

type GetAssertionAuthData struct {
	RPIDHash               []byte
	Flags                  AuthDataFlag
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             *GetExtensionOutputs
}

func ParseGetAssertionAuthData(data []byte) (*GetAssertionAuthData, error) {
	d, err := parseAuthData(data)
	if err != nil {
		return nil, err
	}

	getAssertionAuthData := &GetAssertionAuthData{
		RPIDHash:               d.RPIDHash,
		Flags:                  d.Flags,
		SignCount:              d.SignCount,
		AttestedCredentialData: d.AttestedCredentialData,
	}

	if d.Extensions != nil {
		if err := cbor.NewDecoder(bytes.NewReader(d.Extensions)).
			Decode(&getAssertionAuthData.Extensions); err != nil {
			return nil, err
		}
	}

	return getAssertionAuthData, nil
}
