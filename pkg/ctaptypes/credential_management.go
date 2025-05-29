package ctaptypes

import "github.com/ldclabs/cose/key"

type AuthenticatorCredentialManagementRequest struct {
	SubCommand        CredentialManagementSubCommand       `cbor:"1,keyasint"`
	SubCommandParams  CredentialManagementSubCommandParams `cbor:"2,keyasint,omitzero"`
	PinUvAuthProtocol PinUvAuthProtocol                    `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte                               `cbor:"4,keyasint,omitempty"`
}

type CredentialManagementSubCommandParams struct {
	RPIDHash     []byte                        `cbor:"1,keyasint,omitempty"`
	CredentialID PublicKeyCredentialDescriptor `cbor:"2,keyasint,omitzero"`
	User         PublicKeyCredentialUserEntity `cbor:"3,keyasint,omitzero"`
}

type AuthenticatorCredentialManagementResponse struct {
	ExistingResidentCredentialsCount             uint                          `cbor:"1,keyasint"`
	MaxPossibleRemainingResidentCredentialsCount uint                          `cbor:"2,keyasint"`
	RP                                           PublicKeyCredentialRpEntity   `cbor:"3,keyasint"`
	RPIDHash                                     []byte                        `cbor:"4,keyasint"`
	TotalRPs                                     uint                          `cbor:"5,keyasint"`
	User                                         PublicKeyCredentialUserEntity `cbor:"6,keyasint"`
	CredentialID                                 PublicKeyCredentialDescriptor `cbor:"7,keyasint"`
	PublicKey                                    *key.Key                      `cbor:"8,keyasint"`
	TotalCredentials                             uint                          `cbor:"9,keyasint"`
	CredProtect                                  uint                          `cbor:"10,keyasint"`
	LargeBlobKey                                 []byte                        `cbor:"11,keyasint"`
	ThirdPartyPayment                            bool                          `cbor:"12,keyasint"`
}
