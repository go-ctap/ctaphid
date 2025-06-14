package webauthntypes

type LargeBlobSupport string

const (
	LargeBlobSupportRequired  LargeBlobSupport = "required"
	LargeBlobSupportPreferred LargeBlobSupport = "preferred"
)

type AuthenticationExtensionsLargeBlobInputs struct {
	Support LargeBlobSupport `cbor:"support"`
	Read    bool             `cbor:"read"`
	Write   []byte           `cbor:"write"`
}
type LargeBlobInputs struct {
	LargeBlob AuthenticationExtensionsLargeBlobInputs `cbor:"largeBlob"`
}

type AuthenticationExtensionsLargeBlobOutputs struct {
	Supported bool   `cbor:"supported"`
	Blob      []byte `cbor:"blob"`
	Written   bool   `cbor:"written"`
}

type LargeBlobOutputs struct {
	LargeBlob AuthenticationExtensionsLargeBlobOutputs `cbor:"largeBlob"`
}
