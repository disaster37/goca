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

// Package key provides RSA Key API management for crypto/x509/rsa.
//
// This package makes easy to generate Keys and load RSA from files to be
// used by GoLang applications.
//
// Generating RSA Keys, the files will be saved in the $CAPATH by default.
// For $CAPATH, please check out the GoCA documentation.
package key

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
)

// KeysData represents the RSA keys with Private Key (Key) and Public Key (Public Key).
type KeysData struct {
	Key       *rsa.PrivateKey
	PublicKey *rsa.PublicKey
}

// CreateKeys creates RSA private and public keyData that contains Key and PublicKey.
func CreateKeys(CACommonName, commonName string, bitSize int) (KeysData, error) {
	reader := rand.Reader
	if bitSize == 0 {
		bitSize = 2048
	}

	key, err := rsa.GenerateKey(reader, bitSize)

	if err != nil {
		return KeysData{}, err
	}

	keys := KeysData{
		Key:       key,
		PublicKey: &key.PublicKey,
	}

	return keys, nil
}

// LoadPrivateKey loads a RSA Private Key from a pem contend.
func LoadPrivateKeyFromPem(keyPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(string(keyPem)))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	return privateKey, nil
}

// LoadPublicKey loads a RSA Public Key from a pem contend.
func LoadPublicKeyFromPem(keyPem []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(string(keyPem)))
	publicKey, _ := x509.ParsePKCS1PublicKey(block.Bytes)

	return publicKey, nil
}

// ConvertPrivateKeyFromDerToPem permit to convert private key from DER format to PEM format
func ConvertPrivateKeyFromDerToPem(privateKey *rsa.PrivateKey) (privateKeyPem []byte, err error) {
	pemPrivateKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	var pemBuff bytes.Buffer
	err = pem.Encode(&pemBuff, pemPrivateKey)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}

// ConvertPrivateKeyFromDerToPem permit to convert public key from DER format to PEM format
func ConvertPublicKeyFromDerToPem(publicKey *rsa.PublicKey) (publicKeyPem []byte, err error) {
	
	asn1Bytes, err := asn1.Marshal(publicKey)
	if err != nil {
		return nil, err
	}
	pemPublickey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	var pemBuff bytes.Buffer
	err = pem.Encode(&pemBuff, pemPublickey)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}
