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

// Package cert provides RSA Key API management for crypto/x509 certificates.
//
// This package makes easy to generate and certificates from files to be used
// by GoLang applications.
//
// Generating Certificates (even by Signing), the files will be saved in the
// $CAPATH by default.
// For $CAPATH, please check out the GoCA documentation.
package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
)

const (
	// MinValidCert is the minimal valid time: 1 day
	MinValidCert int = 1
	// MaxValidCert is the maximum valid time: 3650 day
	MaxValidCert int = 3650
	// DefaultValidCert is the default valid time: 397 days
	DefaultValidCert int = 397
)

// ErrCertExists means that the certificate requested already exists
var ErrCertExists = errors.New("certificate already exists")

var ErrParentCANotFound = errors.New("parent CA not found")

func newSerialNumber() (serialNumber *big.Int) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)

	return serialNumber
}

// CreateCSR creates a Certificate Signing Request returning certData with CSR.
// The returned CSR is on DER format
func CreateCSR(CACommonName, commonName, country, province, locality, organization, organizationalUnit, emailAddresses string, dnsNames []string, ipAddresses []net.IP, priv *rsa.PrivateKey) (csrDer []byte, err error) {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	subject := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Province:           []string{province},
		Locality:           []string{locality},
		Organization:       []string{organization},
		OrganizationalUnit: []string{organizationalUnit},
	}

	rawSubj := subject.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddresses},
	})
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddresses},
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        ipAddresses,
	}

	dnsNames = append(dnsNames, commonName)
	template.DNSNames = dnsNames

	return x509.CreateCertificateRequest(rand.Reader, &template, priv)
}

// ConvertCSRFromDerToPem permit to convert CSR from DER format to PEM format
func ConvertCSRFromDerToPem(csrDer []byte) (csrPem []byte, err error) {
	pemCSR := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDer}
	var pemBuff bytes.Buffer
	err = pem.Encode(&pemBuff, pemCSR)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}

// LoadCSR loads a Certificate Signing Request from pem contend.
func LoadCSRFromPem(csrPem []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPem)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	return csr, nil
}

// LoadCRL loads a Certificate Revocation List from a pem contend.
func LoadCRLFromPem(crlPem []byte) (*pkix.CertificateList, error) {
	block, _ := pem.Decode(crlPem)
	crl, _ := x509.ParseCRL(block.Bytes)

	return crl, nil
}

// CreateRootCert creates a Root CA Certificate (self-signed)
func CreateRootCert(
	CACommonName,
	commonName,
	country,
	province,
	locality,
	organization,
	organizationalUnit,
	emailAddresses string,
	valid int,
	dnsNames []string,
	ipAddresses []net.IP,
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
) (certDer []byte, err error) {
	certDer, err = CreateCACert(
		CACommonName,
		commonName,
		country,
		province,
		locality,
		organization,
		organizationalUnit,
		emailAddresses,
		valid,
		dnsNames,
		ipAddresses,
		privateKey,
		nil, // parentPrivateKey
		nil, // parentCertificate
		publicKey)
	return certDer, err
}

// CreateCACert creates a CA Certificate
//
// Root certificates are self-signed. When creating a root certificate, leave
// parentPrivateKey and parentCertificate parameters as nil. When creating an
// intermediate CA certificates, provide parentPrivateKey and parentCertificate
func CreateCACert(
	CACommonName,
	commonName,
	country,
	province,
	locality,
	organization,
	organizationalUnit,
	emailAddresses string,
	validDays int,
	dnsNames []string,
	ipAddresses []net.IP,
	privateKey,
	parentPrivateKey *rsa.PrivateKey,
	parentCertificate *x509.Certificate,
	publicKey *rsa.PublicKey) (certDer []byte, err error) {
	if validDays == 0 {
		validDays = DefaultValidCert
	}
	caCert := &x509.Certificate{
		SerialNumber: newSerialNumber(),
		Subject: pkix.Name{
			CommonName:         commonName,
			Organization:       []string{organization},
			OrganizationalUnit: []string{organizationalUnit},
			Country:            []string{country},
			Province:           []string{province},
			Locality:           []string{locality},
			// TODO: StreetAddress: []string{"ADDRESS"},
			// TODO: PostalCode:    []string{"POSTAL_CODE"},
		},
		NotBefore:             time.Now().Add(-time.Minute * 10),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IPAddresses:           ipAddresses,
	}
	dnsNames = append(dnsNames, commonName)
	caCert.DNSNames = dnsNames

	signingPrivateKey := privateKey
	if parentPrivateKey != nil {
		signingPrivateKey = parentPrivateKey
	}
	signingCertificate := caCert
	if parentCertificate != nil {
		signingCertificate = parentCertificate
	}
	return x509.CreateCertificate(rand.Reader, caCert, signingCertificate, publicKey, signingPrivateKey)

}

// LoadCert loads a certifiate from a pem contend.
func LoadCertFromPem(certString []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(string(certString)))
	cert, _ := x509.ParseCertificate(block.Bytes)
	return cert, nil
}

// ConvertCertificateFromDerToPem permit to convert certificate from DER format to PEM format
func ConvertCertificateFromDerToPem(certDer []byte) (certPem []byte, err error) {
	var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: certDer}
	var pemBuff bytes.Buffer
	err = pem.Encode(&pemBuff, pemCert)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}

// CASignCSR signs an Certificate Signing Request and returns the Certificate as Go bytes.
func CASignCSR(CACommonName string, csr *x509.CertificateRequest, caCert *x509.Certificate, privKey *rsa.PrivateKey, valid int) (certDer []byte, err error) {
	if valid == 0 {
		valid = DefaultValidCert

	} else if valid > MaxValidCert || valid < MinValidCert {
		return nil, errors.Errorf("the certificate valid (min/max) is not between %d - %d", MinValidCert, MaxValidCert)
	}

	csrTemplate := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: newSerialNumber(),
		Issuer:       caCert.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, valid),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	return x509.CreateCertificate(rand.Reader, csrTemplate, caCert, csrTemplate.PublicKey, privKey)
}

// RevokeCertificate is used to revoke a certificate (added to the revoked list)
func RevokeCertificate(CACommonName string, certificateList []pkix.RevokedCertificate, caCert *x509.Certificate, privKey *rsa.PrivateKey) (crlDer []byte, err error) {

	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  caCert.SignatureAlgorithm,
		RevokedCertificates: certificateList,
		Number:              newSerialNumber(),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().AddDate(0, 0, 1),
	}

	return x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, privKey)
}

// ConvertCRLFromDerToPem permit to convert CLR from DER format to PEM format
func ConvertCRLFromDerToPem(crlDer []byte) (crlPem []byte, err error) {
	var pemCRL = &pem.Block{Type: "X509 CRL", Bytes: crlDer}
	var pemBuff bytes.Buffer

	err = pem.Encode(&pemBuff, pemCRL)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), err
}
