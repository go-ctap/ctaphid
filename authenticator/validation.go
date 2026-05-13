package authenticator

import (
	"github.com/go-ctap/ctap/client"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/webauthn"
)

func validateHMACGetSecretSalts(input webauthn.HMACGetSecretInput) error {
	if len(input.Salt1) != 32 {
		return newErrorMessage(ErrInvalidSaltSize, "salt1 must be exactly 32 bytes")
	}
	if input.Salt2 != nil && len(input.Salt2) != 32 {
		return newErrorMessage(ErrInvalidSaltSize, "salt2 must be exactly 32 bytes when present")
	}

	return nil
}

func (d *Device) normalizeAndValidateCurrentPIN(pin string) (string, error) {
	return client.NormalizeAndValidatePIN(pin, protocol.DefaultMinPINCodePoints)
}

func (d *Device) normalizeAndValidateNewPIN(pin string) (string, error) {
	return client.NormalizeAndValidatePIN(pin, d.info.EffectiveMinPINLength())
}
