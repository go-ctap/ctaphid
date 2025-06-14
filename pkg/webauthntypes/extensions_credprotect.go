package webauthntypes

type CredentialProtectionPolicy string

const (
	CredentialProtectionPolicyUserVerificationOptional                     CredentialProtectionPolicy = "userVerificationOptional"
	CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList CredentialProtectionPolicy = "userVerificationOptionalWithCredentialIDList"
	CredentialProtectionPolicyUserVerificationRequired                     CredentialProtectionPolicy = "userVerificationRequired"
)

type CreateCredentialProtectionInputs struct {
	CredentialProtectionPolicy        CredentialProtectionPolicy `cbor:"credentialProtectionPolicy"`
	EnforceCredentialProtectionPolicy bool                       `cbor:"enforceCredentialProtectionPolicy"`
}
