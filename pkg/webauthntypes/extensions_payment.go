package webauthntypes

type PaymentEntityLogo struct {
	URL   string `cbor:"url"`
	Label string `cbor:"label"`
}

type PaymentCurrencyAmount struct {
	Currency string `cbor:"currency"`
	Value    string `cbor:"value"`
}

type PaymentCredentialInstrument struct {
	DisplayName     string `cbor:"displayName"`
	Icon            string `cbor:"icon"`
	IconMustBeShown string `cbor:"iconMustBeShown,omitempty"` // should default to true
	Details         string `cbor:"details,omitempty"`
}

type AuthenticationExtensionsPaymentInputs struct {
	IsPayment                    bool                            `cbor:"payment"`
	BrowserBoundPubKeyCredParams []PublicKeyCredentialParameters `cbor:"browserBoundPubKeyCredParams"`

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
	Signature []byte `cbor:"signature"`
}

type AuthenticationExtensionsPaymentOutputs struct {
	BrowserBoundSignature *BrowserBoundSignature `cbor:"browserBoundSignature,omitempty"`
}

type PaymentOutputs struct {
	Payment AuthenticationExtensionsPaymentOutputs `cbor:"payment"`
}
