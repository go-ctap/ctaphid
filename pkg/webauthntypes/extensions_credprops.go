package webauthntypes

type CreateCredentialPropertiesInputs struct {
	CredentialProperties bool `cbor:"credProps"`
}

type CredentialPropertiesOutput struct {
	ResidentKey bool `cbor:"rk"`
}
type CreateCredentialPropertiesOutputs struct {
	CredentialProperties CredentialPropertiesOutput `cbor:"credProps"`
}
