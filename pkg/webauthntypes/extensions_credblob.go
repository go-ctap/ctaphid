package webauthntypes

type CreateCredentialBlobInputs struct {
	CredBlob []byte `cbor:"credBlob"`
}

type CreateCredentialBlobOutputs struct {
	CredBlob bool `cbor:"credBlob"`
}

type GetCredentialBlobInputs struct {
	GetCredBlob bool `cbor:"getCredBlob"`
}

type GetCredentialBlobOutputs struct {
	GetCredBlob []byte `cbor:"getCredBlob"`
}
