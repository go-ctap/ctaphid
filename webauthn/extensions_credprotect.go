package webauthn

import "github.com/go-ctap/ctap/extension"

type CreateCredentialProtectionInputs struct {
	CredentialProtectionPolicy        extension.CredentialProtectionPolicy `cbor:"credentialProtectionPolicy"`
	EnforceCredentialProtectionPolicy bool                                 `cbor:"enforceCredentialProtectionPolicy"`
}
