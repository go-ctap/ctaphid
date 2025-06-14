package webauthntypes

type AuthenticationExtensionsPRFValues struct {
	First  []byte `cbor:"first"`
	Second []byte `cbor:"second,omitempty"`
}

type AuthenticationExtensionsPRFInputs struct {
	Eval             *AuthenticationExtensionsPRFValues           `cbor:"eval,omitempty"`
	EvalByCredential map[string]AuthenticationExtensionsPRFValues `cbor:"evalByCredential,omitempty"`
}

type PRFInputs struct {
	PRF AuthenticationExtensionsPRFInputs `cbor:"prf"`
}

type AuthenticationExtensionsPRFOutputs struct {
	Enabled bool                              `cbor:"enabled"`
	Results AuthenticationExtensionsPRFValues `cbor:"results"`
}

type PRFOutputs struct {
	PRF AuthenticationExtensionsPRFOutputs `cbor:"prf"`
}
