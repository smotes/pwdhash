package pwdhash_test

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/smotes/pwdhash"
)

const (
	iterationCount = 200000
)

var (
	pwd = []byte("password")
)

func TestMd5Hash(t *testing.T) {
	n := md5.Size
	a := "md5"
	common(t, n, a)
}

func TestSha1Hash(t *testing.T) {
	n := sha1.Size
	a := "sha1"
	common(t, n, a)
}

func TestSha2_256Hash(t *testing.T) {
	n := sha256.Size
	a := "sha256"
	common(t, n, a)
}

func TestSha2_512Hash(t *testing.T) {
	n := sha512.Size
	a := "sha512"
	common(t, n, a)
}

func common(t *testing.T, n int, a string) {
	s, err := pwdhash.GenerateSalt(n)
	if err != nil {
		t.Errorf("Unexpected error from GenerateSalt() using algorithm %s with key size %d: %v", a, n, err)
	}

	hpwd, err := pwdhash.GenerateFromPassword(pwd, s, iterationCount, n, a)
	if err != nil {
		t.Errorf("Unexpected error from GenerateFromPassword() using algorithm %s with key size %d: %v", a, n, err)
	}

	err = pwdhash.CompareHashAndPassword(hpwd, pwd)
	if err != nil {
		t.Errorf("Unexpected error from CompareHashAndPassword() using algorithm %s with key size %d: %v", a, n, err)
	}

	cost, err := pwdhash.Cost(hpwd)
	if err != nil {
		t.Errorf("Unexpected error from Cost() using algorithm %s with key size %d: %v", a, n, err)
	} else if cost != iterationCount {
		t.Errorf("Unexpected result from Cost() using algorithm %s with key size %d: %v", a, n, err)
	}
}
