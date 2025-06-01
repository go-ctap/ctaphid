package device

type CredentialProtectionPolicy string

const (
	CredentialProtectionPolicyUserVerificationOptional                     CredentialProtectionPolicy = "userVerificationOptional"
	CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList CredentialProtectionPolicy = "userVerificationOptionalWithCredentialIDList"
	CredentialProtectionPolicyUserVerificationRequired                     CredentialProtectionPolicy = "userVerificationRequired"
)

type CredProtectInput struct {
	CredentialProtectionPolicy        CredentialProtectionPolicy `cbor:"credentialProtectionPolicy"`
	EnforceCredentialProtectionPolicy bool                       `cbor:"enforceCredentialProtectionPolicy"`
}

type HMACSecretInput struct {
	Salt1 []byte
	Salt2 []byte
}

type HMACSecretOutput struct {
	Output1 []byte
	Output2 []byte
}
