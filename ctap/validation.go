package ctap

import (
	"fmt"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	defaultMinPINCodePoints uint = 4
	maxPINUTF8Bytes         int  = 63
	clientDataHashSize      int  = 32
)

func ValidateClientDataHash(clientDataHash []byte) error {
	if len(clientDataHash) != clientDataHashSize {
		return fmt.Errorf("clientDataHash must be exactly %d bytes", clientDataHashSize)
	}

	return nil
}

func NormalizeAndValidatePIN(pin string, minCodePoints uint) (string, error) {
	if minCodePoints < defaultMinPINCodePoints {
		minCodePoints = defaultMinPINCodePoints
	}

	pin = norm.NFC.String(pin)
	if uint(utf8.RuneCountInString(pin)) < minCodePoints {
		return "", fmt.Errorf("pin must contain at least %d Unicode code points", minCodePoints)
	}
	if len([]byte(pin)) > maxPINUTF8Bytes {
		return "", fmt.Errorf("pin must be at most %d UTF-8 bytes", maxPINUTF8Bytes)
	}
	if pin[len(pin)-1] == 0x00 {
		return "", fmt.Errorf("pin must not end in a 0x00 byte")
	}

	return pin, nil
}

func normalizeAndValidatePIN(pin string) (string, error) {
	return NormalizeAndValidatePIN(pin, defaultMinPINCodePoints)
}
