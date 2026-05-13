package webauthn

import "github.com/go-ctap/ctap/credential"

type PaymentEntityLogo struct {
	URL   string `cbor:"url" json:"url"`
	Label string `cbor:"label" json:"label"`
}

type PaymentCurrencyAmount struct {
	Currency string `cbor:"currency" json:"currency"`
	Value    string `cbor:"value" json:"value"`
}

type PaymentCredentialInstrument struct {
	DisplayName     string `cbor:"displayName" json:"displayName"`
	Icon            string `cbor:"icon" json:"icon"`
	IconMustBeShown string `cbor:"iconMustBeShown,omitempty" json:"iconMustBeShown,omitempty"` // should default to true
	Details         string `cbor:"details,omitempty" json:"details,omitempty"`
}

type AuthenticationExtensionsPaymentInputs struct {
	IsPayment                    bool                                       `cbor:"payment"`
	BrowserBoundPubKeyCredParams []credential.PublicKeyCredentialParameters `cbor:"browserBoundPubKeyCredParams"`

	RPID                 string                       `cbor:"rpId"`
	TopOrigin            string                       `cbor:"topOrigin"`
	PayeeName            string                       `cbor:"payeeName"`
	PayeeOrigin          string                       `cbor:"payeeOrigin"`
	PaymentEntitiesLogos []PaymentEntityLogo          `cbor:"paymentEntitiesLogos"`
	Total                *PaymentCurrencyAmount       `cbor:"total"`
	Instrument           *PaymentCredentialInstrument `cbor:"instrument"`
}
type PaymentInputs struct {
	Payment AuthenticationExtensionsPaymentInputs `cbor:"payment"`
}

type BrowserBoundSignature struct {
	Signature []byte `cbor:"signature" json:"signature"`
}

type AuthenticationExtensionsPaymentOutputs struct {
	BrowserBoundSignature *BrowserBoundSignature `cbor:"browserBoundSignature,omitempty"`
}

type PaymentOutputs struct {
	Payment AuthenticationExtensionsPaymentOutputs `cbor:"payment"`
}
