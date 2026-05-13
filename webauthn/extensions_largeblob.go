package webauthn

import "github.com/go-ctap/ctap/extension"

type AuthenticationExtensionsLargeBlobInputs struct {
	Support extension.LargeBlobSupport `cbor:"support"`
	Read    bool                       `cbor:"read"`
	Write   []byte                     `cbor:"write"`
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
