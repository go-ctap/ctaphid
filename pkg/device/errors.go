package device

import (
	"errors"
)

var (
	ErrPingPongMismatch         = errors.New("device: ping/pong mismatch")
	ErrPinUvAuthTokenRequired   = errors.New("device: pinUvAuthToken required")
	ErrBuiltInUVRequired        = errors.New("device: built-in user verification required")
	ErrNotSupported             = errors.New("device: not supported")
	ErrPinNotSet                = errors.New("device: pin not set")
	ErrPinAlreadySet            = errors.New("device: pin already set")
	ErrUvNotConfigured          = errors.New("device: UV not configured")
	ErrLargeBlobsIntegrityCheck = errors.New("device: large blobs integrity check failed")
	ErrLargeBlobsTooBig         = errors.New("device: size of serialized large blobs is too big that token")
)

type ErrorWithMessage struct {
	Message string
	Err     error
}

func newErrorMessage(err error, msg string) *ErrorWithMessage {
	return &ErrorWithMessage{
		Message: msg,
		Err:     err,
	}
}

func (m *ErrorWithMessage) Error() string {
	if m.Message != "" {
		return m.Err.Error() + " (" + m.Message + ")"
	}
	return m.Err.Error()
}

func (m *ErrorWithMessage) Unwrap() error {
	return m.Err
}
