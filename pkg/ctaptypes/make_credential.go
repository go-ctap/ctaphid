package ctaptypes

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
	"github.com/savely-krasovsky/go-ctaphid/pkg/webauthntypes"
)

type AuthenticatorMakeCredentialRequest struct {
	ClientDataHash               []byte                                               `cbor:"1,keyasint"`
	RP                           webauthntypes.PublicKeyCredentialRpEntity            `cbor:"2,keyasint"`
	User                         webauthntypes.PublicKeyCredentialUserEntity          `cbor:"3,keyasint"`
	PubKeyCredParams             []webauthntypes.PublicKeyCredentialParameters        `cbor:"4,keyasint"`
	ExcludeList                  []webauthntypes.PublicKeyCredentialDescriptor        `cbor:"5,keyasint,omitempty"`
	Extensions                   *CreateExtensionInputs                               `cbor:"6,keyasint,omitempty"`
	Options                      map[Option]bool                                      `cbor:"7,keyasint,omitempty"`
	PinUvAuthParam               []byte                                               `cbor:"8,keyasint,omitempty"`
	PinUvAuthProtocol            PinUvAuthProtocol                                    `cbor:"9,keyasint,omitempty"`
	EnterpriseAttestation        uint                                                 `cbor:"10,keyasint,omitempty"`
	AttestationFormatsPreference []webauthntypes.AttestationStatementFormatIdentifier `cbor:"11,keyasint,omitempty"`
}

type AuthenticatorMakeCredentialResponse struct {
	Format                   webauthntypes.AttestationStatementFormatIdentifier         `cbor:"1,keyasint"`
	AuthDataRaw              []byte                                                     `cbor:"2,keyasint"`
	AuthData                 *MakeCredentialAuthData                                    `cbor:"-"`
	AttestationStatement     map[string]any                                             `cbor:"3,keyasint,omitempty"`
	EnterpriseAttestation    bool                                                       `cbor:"4,keyasint,omitempty"`
	LargeBlobKey             []byte                                                     `cbor:"5,keyasint,omitempty"`
	UnsignedExtensionOutputs map[webauthntypes.ExtensionIdentifier]any                  `cbor:"6,keyasint,omitempty"`
	ExtensionOutputs         *webauthntypes.CreateAuthenticationExtensionsClientOutputs `cbor:"-"`
}

type MakeCredentialAuthData struct {
	RPIDHash               []byte
	Flags                  AuthDataFlag
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             *CreateExtensionOutputs
}

func ParseMakeCredentialAuthData(data []byte) (*MakeCredentialAuthData, error) {
	d, err := parseAuthData(data)
	if err != nil {
		return nil, err
	}

	makeCredentialAuthData := &MakeCredentialAuthData{
		RPIDHash:               d.RPIDHash,
		Flags:                  d.Flags,
		SignCount:              d.SignCount,
		AttestedCredentialData: d.AttestedCredentialData,
	}

	if d.Extensions != nil {
		if err := cbor.NewDecoder(bytes.NewReader(d.Extensions)).
			Decode(&makeCredentialAuthData.Extensions); err != nil {
			return nil, err
		}
	}

	return makeCredentialAuthData, nil
}
