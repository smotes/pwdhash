# pwdhash [![Build Status](https://drone.io/github.com/smotes/pwdhash/status.png)](https://drone.io/github.com/smotes/pwdhash/latest) [![GoDoc](https://godoc.org/github.com/smotes/pwdhash?status.svg)](https://godoc.org/github.com/smotes/pwdhash)

### Overview

`pwdhash` is a Go package for securely hashing passwords and for checking plaintext password guesses against a
hashed password.

This package uses the PBKDF2 key derivation algorithm with HMAC variant in combination with a supplied hash function
and cryptographically-secure, randomly-generated salt to achieve secure password hashing.

Note that while alternatives, such as bcrypt and scrypt, do exist, PBKDF2 is considered appropriate and secure for
password hashing if used correctly (ie: appropriately high cost factor, secure hashing algorithm, unique salt per password).


### Example

The following code uses HMAC-SHA-512 based PBKDF2 to protect the password `"password"` with a cost factor of 100,000 iterations.

```go
package main

import (
    "crypto/sha512"

    "github.com/smotes/pwdhash"
)

func main() {
    pwd := []byte("password")
    cost := 100000  // cost as number of pbkdf2 iterations

    salt, err := pwdhash.GenerateSalt(sha512.Size)
    if err != nil {
        panic(err)
    }

    hpwd, err := pwdhash.GenerateFromPassword(pwd, salt, cost, sha512.Size, "sha512")
    if err != nil {
        panic(err)
    }

    err = pwdhash.CompareHashAndPassword(hpwd, pwd)
    if err != nil {
        panic(err)  // err = ErrMismatchedHashAndPassword
    }
}
```

