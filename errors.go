package pwdhash

import (
	"errors"
	"fmt"
)

// The error returned from GenerateFromPassword when the provided work factor is
// outside of the valid range.
type ErrInvalidCost int

func (err ErrInvalidCost) Error() string {
	return fmt.Sprintf("github.com/smotes/phash: cost %d is outside the valid range of iterations [%d, %d]",
		int(err), MinCost, MaxCost)
}

// The error returned from GenerateFromPassword when the provided hash function is
// not supported/invalid.
type ErrInvalidHashFunction string

func (err ErrInvalidHashFunction) Error() string {
	return fmt.Sprintf("github.com/smotes/phash: hash function %s is not supported/valid", string(err))
}

// The error returned from CompareHashAndPassword when the hashed password does not
// match the hash of the given password.
var ErrMismatchedHashAndPassword = errors.New("github.com/smotes/phash: hashed password is not the hash of the given password")
