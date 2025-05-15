package ctaphid

import (
	"errors"

	"github.com/savely-krasovsky/go-ctaphid/pkg/ctaptypes"
)

var (
	ErrMessageTooLarge        = errors.New("ctaphid: message payload too large")
	ErrUnexpectedCommand      = errors.New("ctaphid: unexpected command")
	ErrInvalidResponseMessage = errors.New("ctaphid: invalid response message")
)

type CTAPError struct {
	Command    ctaptypes.Command
	StatusCode StatusCode
}

func newCTAPError(cmd ctaptypes.Command, code StatusCode) *CTAPError {
	return &CTAPError{
		Command:    cmd,
		StatusCode: code,
	}
}

func (e *CTAPError) Error() string {
	return e.Command.String() + " failed (" + e.StatusCode.String() + ")"
}

func (e *CTAPError) Unwrap() error {
	return errors.New(e.StatusCode.String())
}
