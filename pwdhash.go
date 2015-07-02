package pwdhash

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

// CompareHashAndPassword compares a PBKDF2 hashed password hpwd with its
// possible plaintext equivalent pwd. Returns nil on success, or an error
// on failure.
//
// The comparison is done using a constant-length comparison algorithm
// to protect against possible timing attacks.
func CompareHashAndPassword(hpwd, pwd []byte) error {
	alg, cost, salt, digest, err := validateHashFormat(hpwd)
	if err != nil {
		return err
	}

	n := len(digest)

	guess, err := GenerateFromPassword(pwd, salt, cost, n, alg)
	if err != nil {
		return err
	}

	res := subtle.ConstantTimeCompare(hpwd, guess)
	if res != 1 {
		return ErrMismatchedHashAndPassword
	}
	return nil
}

// Cost returns the work factor used to create the given hashed password.
// When, in the future, the work factor needs to be increased in order to
// adjust for greater computational power, this function allows one to
// establish which passwords need to be updated.
func Cost(hpwd []byte) (int, error) {
	bs := bytes.Split(hpwd, delim)
	cost, err := strconv.ParseUint(string(bs[costIndex]), base, bitSize)
	if err != nil {
		return -1, err
	}
	return int(cost), nil
}

// GenerateFromPassword returns the PBKDF2 hash of the password from the
// given plaintext password pwd, salt s, number of iterations cost, key length n
// and name of the hash algorithm a.
//
// The cost is the work factor, or number of iterations. Returns an error if
// cost < 1, or if cost > 2^31.
//
// The name of the hash function a must be a one of a number of supported
// one-way hash functions. Returns an error if an unsupported hash algorithm
// name is provided. The list of supported hash algorithm names are:
//
// 		"md5"
// 		"sha1"
//		"sha256"
//		"sha512"
//
// Note that use of md5 or sha1 is not recommended as both are considered
// cryptographically broken, but are still supported for compatibility purposes.
// It is recommended to use sha256 and sha512 on 32-bit and 64-bit systems respectively.
//
// Returns a byte slice containing the name of the hash algorithm, the cost,
// the salt and the password digest. Each component in the output is delimited
// by a '$' character. The cost, salt and digest are encoded in base64 format
// for storage in a database.
//
// <algorithm>$<cost>$<salt>$<digest>
func GenerateFromPassword(pwd, s []byte, cost, n int, alg string) ([]byte, error) {
	if n < MinCost || n > MaxCost {
		return nil, ErrInvalidCost(cost)
	}
	fn, ok := algorithms[alg]
	if !ok {
		return nil, ErrInvalidHashFunction(alg)
	}
	d := pbkdf2.Key(pwd, s, cost, n, fn)

	cs := strconv.FormatUint(uint64(cost), base)
	ss := encode(s)
	ds := encode(d)

	return bytes.Join([][]byte{
		[]byte(alg),
		[]byte(cs),
		ss,
		ds,
	}, delim), nil
}

// GenerateSalt generates a cryptographically secure random salt s of
// specified byte length n.
//
// On return, len(s) == n if and only if err == nil.
//
// Do not reuse the same salt on multiple password hashes.
//
// Do not make the salt too short. A common rule of thumb is to make
// the salt the same byte size as the digest.
func GenerateSalt(n int) (s []byte, err error) {
	s = make([]byte, n)
	_, err = rand.Read(s)
	return
}

func encode(b []byte) []byte {
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(buf, b)
	return buf
}

func decode(b []byte) ([]byte, error) {
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	_, err := base64.StdEncoding.Decode(buf, b)
	if err != nil {
		return nil, err
	}
	buf = bytes.TrimRight(buf, null)
	return buf, nil
}

func validateHashFormat(hpwd []byte) (alg string, cost int, salt, digest []byte, err error) {
	// check number of parts in encoded password hash split by delimiter
	bs := bytes.Split(hpwd, delim)
	if len(bs) != 4 {
		return "", 0, nil, nil, ErrInvalidHashFormat("invalid number of parts")
	}

	// verify algorithm is supported
	alg = string(bs[algorithmIndex])
	_, ok := algorithms[alg]
	if !ok {
		return "", 0, nil, nil, ErrInvalidHashFunction(alg)
	}

	// verify format of string encoded cost
	cost, err = Cost(hpwd)
	if err != nil {
		return "", 0, nil, nil, ErrInvalidHashFormat("invalid cost")
	}

	// verify format of salt as base64 encoded
	salt, err = decode(bs[saltIndex])
	if err != nil {
		return "", 0, nil, nil, ErrInvalidHashFormat("invalid salt encoding")
	}

	// verify format of digest as base64 encoded
	digest, err = decode(bs[digestIndex])
	if err != nil {
		return "", 0, nil, nil, ErrInvalidHashFormat("invalid digest encoding")
	}

	return alg, cost, salt, digest, nil
}
