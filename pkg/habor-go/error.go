package harbor_go

import (
	"fmt"
	"github.com/pkg/errors"
)

type HarborError struct {
	error     error
	errorCode ErrorCode
	errorMsg  string
}

func NewHarborError(code ErrorCode, msg string) HarborError {
	c := HarborError{errorCode: code, errorMsg: msg}
	e := errors.New(fmt.Sprintf("Code: %s | %s\n", code, msg))
	c.error = errors.WithStack(e)
	return c
}

func (c HarborError) ErrorCode() ErrorCode {
	return c.errorCode
}

func (c HarborError) ToError() error {
	return c.error
}

func (c HarborError) Error() string {
	return c.error.Error()
}

func (c HarborError) ErrorMessage() string {
	return c.errorMsg
}

func (c HarborError) ToString() string {
	return fmt.Sprintf("Code: %s, Msg: %s", c.errorCode, c.errorMsg)
}

type ErrorCode string

func (e ErrorCode) ToString() string {
	return fmt.Sprintf("%s", e)
}

const (
	ErrorUnknown       ErrorCode = "Unknown"
	ErrorNotFound      ErrorCode = "NotFound"
	ErrorAlreadyExists ErrorCode = "AlreadyExist"
	ErrorUnauthorized  ErrorCode = "Unauthorized"
	ErrorForbidden     ErrorCode = "Forbidden"
	ErrorConflict      ErrorCode = "Conflict"
	ErrorGone          ErrorCode = "Gone"
	ErrorInvalid       ErrorCode = "Invalid"
	ErrorServerTimeout ErrorCode = "ServerTimeout"
	ErrorTimeout       ErrorCode = "Timeout"
	ErrorInternal      ErrorCode = "Internal"
	ErrorBadRequest    ErrorCode = "BadRequest"
)

func IsNotFound(e error) bool {
	switch e.(type) {
	case HarborError:
		if e.(HarborError).errorCode == ErrorNotFound {
			return true
		}
	}
	return false
}
