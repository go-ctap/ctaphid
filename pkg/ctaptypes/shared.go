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

type AttestedCredentialData struct {
	AAGUID              uuid.UUID
	CredentialID        []byte
	CredentialPublicKey key.Key
}
