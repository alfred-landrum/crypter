// Package crypter provides convienence wrapping around the nacl/secretbox
// package.
package crypter

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// Sizes and minimums set by secretbox
const (
	KeySize = 32

	// 24 bytes for nonce + minimum secretbox length
	Overhead = 24 + secretbox.Overhead
)

// A Box is generated from a Key, and can encrypt & decrypt "small" messages,
// using nacl/secretbox.
type Box struct {
	Key [KeySize]byte
}

// A Key is a base64 RawURLEncoded 32 byte sequence.
type Key string

// NewKey generates a new appropriately sized key.
func NewKey() Key {
	var k [KeySize]byte
	_, err := io.ReadFull(rand.Reader, k[:])
	if err != nil {
		panic(fmt.Errorf("rand.Reader failed %v", err))
	}
	return Key(base64.RawURLEncoding.EncodeToString(k[:]))
}

// NewBox creates a new crypter box from the given key, failing only if the key
// wasn't created from NewKey.
func NewBox(key Key) (*Box, error) {
	b := &Box{}
	sbytes, err := base64.RawURLEncoding.DecodeString(string(key))
	if err != nil {
		return nil, errors.New("bad key encoding")
	}
	if len(sbytes) != KeySize {
		return nil, errors.New("bad key length")
	}

	copy(b.Key[:], sbytes[:])
	return b, nil
}

// Encrypt uses secretbox.Seal to authenticate & encrypt the data.
func (b *Box) Encrypt(data []byte) []byte {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic(fmt.Errorf("rand.Reader failed %v", err))
	}

	return secretbox.Seal(nonce[:], data, &nonce, &b.Key)
}

// Decrypt uses secretbox.Open to authenticate & decrypt data.
func (b *Box) Decrypt(data []byte) ([]byte, error) {
	if len(data) < Overhead {
		// must be at least the size of nonce + minimal secretbox length
		return nil, errors.New("data too small")
	}
	var nonce [24]byte
	copy(nonce[:], data[:24])

	clear, ok := secretbox.Open(nil, data[24:], &nonce, &b.Key)
	if !ok {
		return nil, errors.New("decrypt failed")
	}

	return clear, nil
}
