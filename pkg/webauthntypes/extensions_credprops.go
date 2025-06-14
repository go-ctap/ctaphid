package webauthntypes

type CreateCredentialPropertiesInputs struct {
	CredentialProperties bool `cbor:"credProps"`
}

type CredentialPropertiesOutput struct {
	RequireResidentKey bool `cbor:"rk"`
}
type CreateCredentialPropertiesOutputs struct {
	CredentialProperties CredentialPropertiesOutput `cbor:"credProps"`
}
