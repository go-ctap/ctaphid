package ctaptypes

import (
	"github.com/google/uuid"
	"github.com/ldclabs/cose/key"
)

type AuthDataFlag byte

const (
	AuthDataFlagUserPresent AuthDataFlag = 1 << iota
	_
	AuthDataFlagUserVerified
	_
	_
	_
	AuthDataFlagAttestedCredentialDataIncluded
	AuthDataFlagExtensionDataIncluded
)

type AuthData struct {
	RPIDHash               []byte
	Flags                  AuthDataFlag
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             map[ExtensionIdentifier]any
}

type AttestedCredentialData struct {
	AAGUID              uuid.UUID
	CredentialID        []byte
	CredentialPublicKey key.Key
}
