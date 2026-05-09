package device

import (
	"github.com/go-ctap/ctaphid/pkg/ctap"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
)

func validateHMACGetSecretSalts(input webauthntypes.HMACGetSecretInput) error {
	if len(input.Salt1) != 32 {
		return newErrorMessage(ErrInvalidSaltSize, "salt1 must be exactly 32 bytes")
	}
	if input.Salt2 != nil && len(input.Salt2) != 32 {
		return newErrorMessage(ErrInvalidSaltSize, "salt2 must be exactly 32 bytes when present")
	}

	return nil
}

func (d *Device) normalizeAndValidateCurrentPIN(pin string) (string, error) {
	return ctap.NormalizeAndValidatePIN(pin, ctaptypes.DefaultMinPINCodePoints)
}

func (d *Device) normalizeAndValidateNewPIN(pin string) (string, error) {
	return ctap.NormalizeAndValidatePIN(pin, d.info.EffectiveMinPINLength())
}
