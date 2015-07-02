// Package pwdhash is a Go package for securely hashing passwords and for
// checking plaintext password guesses against a hashed password.
//
// This package uses the PBKDF2 key derivation algorithm with HMAC variant
// in combination with a supplied hash function and cryptographically-secure,
// randomly-generated salt to achieve secure password hashing.
//
// Note that while alternatives, such as bcrypt and scrypt, do exist, PBKDF2 is
// considered appropriate and secure for password hashing if used correctly
// (ie: appropriately high cost factor, secure hashing algorithm, unique salt per password).
//
package pwdhash // import "github.com/smotes/pwdhash"
