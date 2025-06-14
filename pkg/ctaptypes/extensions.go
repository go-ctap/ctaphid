package ctaptypes

import "github.com/ldclabs/cose/key"

type CreateCredProtectInput struct {
	CredProtect int `cbor:"credProtect"`
}
type CreateCredBlobInput struct {
	CredBlob []byte `cbor:"credBlob"`
}
type CreateMinPinLengthInput struct {
	MinPinLength bool `cbor:"minPinLength"`
}
type CreatePinComplexityPolicyInput struct {
	PinComplexityPolicy bool `cbor:"pinComplexityPolicy"`
}
type CreateHMACSecretInput struct {
	HMACSecret bool `cbor:"hmac-secret"`
}
type CreateHMACSecretMCInput struct {
	HMACSecret HMACSecret `cbor:"hmac-secret-mc"`
}
type CreateThirdPartyPaymentInput struct {
	ThirdPartyPayment bool `cbor:"thirdPartyPayment"`
}

type CreateExtensionInputs struct {
	*CreateCredProtectInput
	*CreateCredBlobInput
	*CreateMinPinLengthInput
	*CreatePinComplexityPolicyInput
	*CreateHMACSecretInput
	*CreateHMACSecretMCInput
	*CreateThirdPartyPaymentInput
}

type CreateCredProtectOutput struct {
	CredProtect int `cbor:"credProtect"`
}
type CreateCredBlobOutput struct {
	CredBlob bool `cbor:"credBlob"`
}
type CreateMinPinLengthOutput struct {
	MinPinLength uint `cbor:"minPinLength"`
}
type CreatePinComplexityPolicyOutput struct {
	PinComplexityPolicy bool `cbor:"pinComplexityPolicy"`
}
type CreateHMACSecretOutput struct {
	HMACSecret bool `cbor:"hmac-secret"`
}
type CreateHMACSecretMCOutput struct {
	HMACSecret []byte `cbor:"hmac-secret-mc"`
}

type CreateExtensionOutputs struct {
	*CreateCredProtectOutput
	*CreateCredBlobOutput
	*CreateMinPinLengthOutput
	*CreatePinComplexityPolicyOutput
	*CreateHMACSecretOutput
	*CreateHMACSecretMCOutput
}

type GetCredBlobInput struct {
	CredBlob bool `cbor:"credBlob"`
}
type HMACSecret struct {
	KeyAgreement      key.Key           `cbor:"1,keyasint"`
	SaltEnc           []byte            `cbor:"2,keyasint"`
	SaltAuth          []byte            `cbor:"3,keyasint"`
	PinUvAuthProtocol PinUvAuthProtocol `cbor:"4,keyasint,omitempty"`
}
type GetHMACSecretInput struct {
	HMACSecret HMACSecret `cbor:"hmac-secret"`
}
type GetThirdPartyPaymentInput struct {
	ThirdPartyPayment bool `cbor:"thirdPartyPayment"`
}

type GetExtensionInputs struct {
	*GetCredBlobInput
	*GetHMACSecretInput
	*GetThirdPartyPaymentInput
}

type GetCredBlobOutput struct {
	CredBlob []byte `cbor:"credBlob"`
}
type GetHMACSecretOutput struct {
	HMACSecret []byte `cbor:"hmac-secret"`
}
type GetThirdPartyPaymentOutput struct {
	ThirdPartyPayment bool `cbor:"thirdPartyPayment"`
}

type GetExtensionOutputs struct {
	*GetCredBlobOutput
	*GetHMACSecretOutput
	*GetThirdPartyPaymentOutput
}
