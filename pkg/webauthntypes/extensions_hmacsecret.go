package webauthntypes

type CreateHMACSecretInputs struct {
	HMACCreateSecret bool `cbor:"hmacCreateSecret"`
}

type CreateHMACSecretOutputs struct {
	HMACCreateSecret bool `cbor:"hmacCreateSecret"`
}

type HMACGetSecretInput struct {
	Salt1 []byte `cbor:"salt1"`
	Salt2 []byte `cbor:"salt2,omitempty"`
}

type GetHMACSecretInputs struct {
	HMACGetSecret HMACGetSecretInput `cbor:"hmacGetSecret"`
}

type HMACGetSecretOutput struct {
	Output1 []byte `cbor:"output1"`
	Output2 []byte `cbor:"output2,omitempty"`
}

type GetHMACSecretOutputs struct {
	HMACGetSecret HMACGetSecretOutput `cbor:"hmacGetSecret"`
}

type CreateHMACSecretMCInputs struct {
	HMACGetSecret HMACGetSecretInput `cbor:"hmacGetSecret"`
}

type CreateHMACSecretMCOutputs struct {
	HMACGetSecret HMACGetSecretOutput `cbor:"hmacGetSecret"`
}
