package errors

import "errors"

var (
	ErrResourceNotFound = errors.New("resource not found")
)

func IsResourceNotFound(err error) bool {
	return errors.Is(err, ErrResourceNotFound)
}
