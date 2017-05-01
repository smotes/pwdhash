package pwdhash

import (
	"errors"
	"fmt"
)

// ErrInvalidCost is returned from the GenerateFromPassword function when the provided work factor is outside of the valid range.
type ErrInvalidCost int

func (err ErrInvalidCost) Error() string {
	return fmt.Sprintf("github.com/smotes/phash: cost %d is outside the valid range of iterations [%d, %d]",
		int(err), MinCost, MaxCost)
}

// ErrInvalidHashFunction is returned from the GenerateFromPassword function when the provided hash function is not supported/invalid.
type ErrInvalidHashFunction string

func (err ErrInvalidHashFunction) Error() string {
	return fmt.Sprintf("github.com/smotes/phash: hash function %s is not supported/valid",
		string(err))
}

// ErrInvalidHashFormat is returned from the CompareHashAndPassword function when the provided hashed password hpwd does not have the expected format.
type ErrInvalidHashFormat string

func (err ErrInvalidHashFormat) Error() string {
	return fmt.Sprintf("github.com/smotes/phash: hashed password is not of the expected format: %s",
		string(err))
}

// ErrMismatchedHashAndPassword is returned from the CompareHashAndPassword function when the hashed password does not match the hash of the given password.
var ErrMismatchedHashAndPassword = errors.New("github.com/smotes/phash: hashed password is not the hash of the given password")
