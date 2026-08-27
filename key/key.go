// MIT License
//
// Copyright (c) 2020, Kairo de Araujo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package key provides RSA key generation, loading, and PEM conversion.
//
// This package handles RSA key creation, PEM encoding/decoding for both
// private and public keys (PKCS#1, PKCS#8, PKIX/SPKI). It is a pure library:
// it does not touch the filesystem. The caller is responsible for persisting
// PEM-encoded data.
package key

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

// Key bit size boundaries.
const (
	// MinKeyBitSize is the minimum accepted RSA key size.
	MinKeyBitSize = 2048
	// DefaultKeyBitSize is used when bitSize is 0.
	DefaultKeyBitSize = 2048
)

// KeysData represents the RSA keys with Private Key (Key) and Public Key (Public Key).
type KeysData struct {
	Key       *rsa.PrivateKey
	PublicKey *rsa.PublicKey
}

// ErrKeyBitSizeTooSmall is returned when the requested key size is below MinKeyBitSize.
var ErrKeyBitSizeTooSmall = errors.Errorf("key bit size must be at least %d", MinKeyBitSize)

// CreateKeys creates RSA private and public keyData that contains Key and PublicKey.
// CACommonName and commonName are deprecated and ignored (kept for backward compatibility).
func CreateKeys(CACommonName, commonName string, bitSize int) (KeysData, error) {
	if bitSize == 0 {
		bitSize = DefaultKeyBitSize
	}
	if bitSize < MinKeyBitSize {
		return KeysData{}, ErrKeyBitSizeTooSmall
	}
	if bitSize%8 != 0 {
		return KeysData{}, errors.New("key bit size must be a multiple of 8")
	}

	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return KeysData{}, err
	}

	keys := KeysData{
		Key:       key,
		PublicKey: &key.PublicKey,
	}

	return keys, nil
}

// LoadPrivateKeyFromPem loads an RSA private key from a PEM block.
// Accepts both "RSA PRIVATE KEY" (PKCS#1) and "PRIVATE KEY" (PKCS#8) blocks.
func LoadPrivateKeyFromPem(keyPem []byte) (*rsa.PrivateKey, error) {
	if len(keyPem) == 0 {
		return nil, errors.New("private key PEM data is empty")
	}
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, errors.New("failed to decode private key PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PKCS#1 private key")
		}
		return privateKey, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PKCS#8 private key")
		}
		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 private key is not an RSA key")
		}
		return privateKey, nil
	default:
		return nil, errors.Errorf("unexpected PEM block type %q for a private key", block.Type)
	}
}

// LoadPublicKeyFromPem loads an RSA public key from a PEM block.
// Accepts both "PUBLIC KEY" (PKIX/SPKI) and "RSA PUBLIC KEY" (PKCS#1) blocks.
func LoadPublicKeyFromPem(keyPem []byte) (*rsa.PublicKey, error) {
	if len(keyPem) == 0 {
		return nil, errors.New("public key PEM data is empty")
	}
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, errors.New("failed to decode public key PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PKIX public key")
		}
		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("PKIX public key is not an RSA key")
		}
		return publicKey, nil
	case "RSA PUBLIC KEY":
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PKCS#1 public key")
		}
		return publicKey, nil
	default:
		return nil, errors.Errorf("unexpected PEM block type %q for a public key", block.Type)
	}
}

// ConvertPrivateKeyFromDerToPem converts an RSA private key to a PEM block
// using the PKCS#8 format ("PRIVATE KEY").
func ConvertPrivateKeyFromDerToPem(privateKey *rsa.PrivateKey) (privateKeyPem []byte, err error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal PKCS#8 private key")
	}
	pemPrivateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}
	var pemBuff bytes.Buffer
	err = pem.Encode(&pemBuff, pemPrivateKey)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}

// ConvertRsaPrivateKeyFromDerToPem converts an RSA private key to a PEM block
// using the PKCS#1 format ("RSA PRIVATE KEY").
func ConvertRsaPrivateKeyFromDerToPem(privateKey *rsa.PrivateKey) (rsaPrivateKeyPem []byte, err error) {
	pemRsaPrivateKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	var pemBuff bytes.Buffer
	err = pem.Encode(&pemBuff, pemRsaPrivateKey)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}

// ConvertPublicKeyFromDerToPem converts an RSA public key to a PEM block
// using the PKIX/SPKI format ("PUBLIC KEY").
func ConvertPublicKeyFromDerToPem(publicKey *rsa.PublicKey) (publicKeyPem []byte, err error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal PKIX public key")
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	var pemBuff bytes.Buffer
	if err := pem.Encode(&pemBuff, pemBlock); err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}
