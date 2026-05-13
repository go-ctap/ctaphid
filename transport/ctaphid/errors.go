package ctaphid

import (
	"errors"

	"github.com/go-ctap/ctap/protocol"
)

var (
	ErrMessageTooLarge        = errors.New("ctaphid: message payload too large")
	ErrInvalidRequestMessage  = errors.New("ctaphid: invalid request message")
	ErrUnexpectedCommand      = errors.New("ctaphid: unexpected command")
	ErrInvalidResponseMessage = errors.New("ctaphid: invalid response message")
)

type CTAPError struct {
	Command    protocol.Command
	StatusCode StatusCode
}

func newCTAPError(cmd protocol.Command, code StatusCode) *CTAPError {
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
