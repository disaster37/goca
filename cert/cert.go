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

// Package cert provides certificate and CSR management for crypto/x509.
//
// This package handles certificate generation, CSR creation, CRL management,
// and PEM/DER conversion. It is a pure library: it does not touch the
// filesystem. The caller is responsible for persisting PEM-encoded data.
package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
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
	// MinValidCert is the minimal valid time for end-entity certificates: 1 day.
	MinValidCert int = 1
	// MaxValidCert is the maximum valid time for end-entity certificates: 3650 days.
	MaxValidCert int = 3650
	// DefaultValidCert is the default valid time for end-entity certificates: 397 days.
	DefaultValidCert int = 397

	// MinValidCACert is the minimal valid time for a CA certificate: 1 day.
	MinValidCACert int = 1
	// MaxValidCACert is the maximum valid time for a CA certificate: 3650 days.
	MaxValidCACert int = 3650
	// DefaultValidCACert is the default valid time for a CA certificate: 3650 days (~10 years).
	DefaultValidCACert int = 3650

	// MinValidDuration is the minimal validity for duration-based issuance: 1 minute.
	MinValidDuration = time.Minute
)

// ErrCertExists means that the certificate requested already exists
var ErrCertExists = errors.New("certificate already exists")

var ErrParentCANotFound = errors.New("parent CA not found")

// ErrCSRSignatureInvalid means that the CSR signature verification failed.
var ErrCSRSignatureInvalid = errors.New("CSR signature is invalid")

// newSerialNumber returns a random positive serial number fitting in 128 bits.
func newSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate serial number")
	}
	// Guarantee positivity (RFC 5280 §4.1.2.2).
	if n.Sign() <= 0 {
		return newSerialNumber()
	}
	return n, nil
}

// CreateCSR creates a Certificate Signing Request (DER bytes).
// CACommonName is deprecated and ignored (kept for backward compatibility).
// commonName is appended to dnsNames if not already present.
func CreateCSR(CACommonName, commonName, country, province, locality, organization, organizationalUnit, emailAddresses string, dnsNames []string, ipAddresses []net.IP, priv crypto.Signer) (csrDer []byte, err error) {
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
	if emailAddresses != "" {
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: emailAddresses},
		})
	}
	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CSR subject")
	}
	template := x509.CertificateRequest{
		RawSubject:  asn1Subj,
		IPAddresses: ipAddresses,
	}
	if emailAddresses != "" {
		template.EmailAddresses = []string{emailAddresses}
	}

	// Build a new slice to avoid mutating the caller's dnsNames and append
	// the commonName only if it is not already present (dedupe).
	allDNS := make([]string, 0, len(dnsNames)+1)
	allDNS = append(allDNS, dnsNames...)
	present := false
	for _, dns := range dnsNames {
		if dns == commonName {
			present = true
			break
		}
	}
	if !present {
		allDNS = append(allDNS, commonName)
	}
	template.DNSNames = allDNS

	return x509.CreateCertificateRequest(rand.Reader, &template, priv)
}

// ConvertCSRFromDerToPem converts a CSR from DER format to PEM format.
func ConvertCSRFromDerToPem(csrDer []byte) (csrPem []byte, err error) {
	pemCSR := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDer}
	var pemBuff bytes.Buffer
	err = pem.Encode(&pemBuff, pemCSR)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}

// LoadCSRFromPem loads a Certificate Signing Request from a PEM block.
func LoadCSRFromPem(csrPem []byte) (*x509.CertificateRequest, error) {
	if len(csrPem) == 0 {
		return nil, errors.New("CSR PEM data is empty")
	}
	block, _ := pem.Decode(csrPem)
	if block == nil {
		return nil, errors.New("failed to decode CSR PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CSR")
	}
	return csr, nil
}

// LoadCRLFromPem loads a Certificate Revocation List from a PEM block.
func LoadCRLFromPem(crlPem []byte) (*x509.RevocationList, error) {
	if len(crlPem) == 0 {
		return nil, errors.New("CRL PEM data is empty")
	}
	block, _ := pem.Decode(crlPem)
	if block == nil {
		return nil, errors.New("failed to decode CRL PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CRL")
	}
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
	privateKey crypto.Signer,
	publicKey crypto.PublicKey,
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
	privateKey crypto.Signer,
	parentPrivateKey crypto.Signer,
	parentCertificate *x509.Certificate,
	publicKey crypto.PublicKey) (certDer []byte, err error) {
	if validDays == 0 {
		validDays = DefaultValidCACert
	}
	if validDays < MinValidCACert {
		return nil, errors.Errorf("CA certificate valid days %d is below minimum %d", validDays, MinValidCACert)
	}
	if validDays > MaxValidCACert {
		return nil, errors.Errorf("CA certificate valid days %d exceeds maximum %d", validDays, MaxValidCACert)
	}
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
	caCert := &x509.Certificate{
		SerialNumber: serial,
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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IPAddresses:           ipAddresses,
	}
	allDNS := make([]string, 0, len(dnsNames)+1)
	allDNS = append(allDNS, dnsNames...)
	present := false
	for _, dns := range dnsNames {
		if dns == commonName {
			present = true
			break
		}
	}
	if !present {
		allDNS = append(allDNS, commonName)
	}
	caCert.DNSNames = allDNS

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

// LoadCertFromPem loads a certificate from a PEM block.
func LoadCertFromPem(certPem []byte) (*x509.Certificate, error) {
	if len(certPem) == 0 {
		return nil, errors.New("certificate PEM data is empty")
	}
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}
	return cert, nil
}

// ConvertCertificateFromDerToPem converts a certificate from DER format to PEM format.
func ConvertCertificateFromDerToPem(certDer []byte) (certPem []byte, err error) {
	var pemCert = &pem.Block{Type: "CERTIFICATE", Bytes: certDer}
	var pemBuff bytes.Buffer
	err = pem.Encode(&pemBuff, pemCert)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}

// SignOptions controls how a CSR is signed into an end-entity certificate.
type SignOptions struct {
	// ValidDays is the validity in days (1..3650). 0 = DefaultValidCert.
	// Ignored when ValidDuration > 0.
	ValidDays int
	// ValidDuration is a duration-based validity. Overrides ValidDays when
	// > 0. Clamped between MinValidDuration and MaxValidCert days.
	ValidDuration time.Duration
	// CertType selects KeyUsage/ExtKeyUsage (see ParseCertType).
	// Empty = DefaultCertType ("server-client").
	CertType string
	// NotBefore sets the certificate validity start explicitly. Zero =
	// computed from now and Backdate.
	NotBefore time.Time
	// Backdate shifts NotBefore into the past (clock-skew tolerance) when
	// NotBefore is zero. Never earlier than the CA's own NotBefore.
	Backdate time.Duration
}

// CASignCSRWithOptions signs a CSR with full control over validity window
// and certificate type. The leaf NotAfter is clamped to the CA's NotAfter.
//
// CACommonName is deprecated and ignored (kept for backward compatibility).
func CASignCSRWithOptions(CACommonName string, csr *x509.CertificateRequest, caCert *x509.Certificate, privKey crypto.Signer, opts SignOptions) (certDer []byte, err error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.Wrapf(ErrCSRSignatureInvalid, "CSR signature verification failed: %v", err)
	}

	now := time.Now()
	var notAfter time.Time
	if opts.ValidDuration > 0 {
		if opts.ValidDuration < MinValidDuration {
			return nil, errors.Errorf("certificate valid duration %s is below minimum %s", opts.ValidDuration, MinValidDuration)
		}
		maxValidDuration := time.Duration(MaxValidCert) * 24 * time.Hour
		if opts.ValidDuration > maxValidDuration {
			return nil, errors.Errorf("certificate valid duration %s exceeds maximum %s", opts.ValidDuration, maxValidDuration)
		}
		notAfter = now.Add(opts.ValidDuration)
	} else {
		days := opts.ValidDays
		if days == 0 {
			days = DefaultValidCert
		} else if days > MaxValidCert || days < MinValidCert {
			return nil, errors.Errorf("the certificate valid (min/max) is not between %d - %d", MinValidCert, MaxValidCert)
		}
		notAfter = now.AddDate(0, 0, days)
	}

	var notBefore time.Time
	if !opts.NotBefore.IsZero() {
		notBefore = opts.NotBefore
	} else {
		notBefore = now
		if opts.Backdate > 0 {
			notBefore = now.Add(-opts.Backdate)
		}
	}

	if notBefore.Before(caCert.NotBefore) {
		notBefore = caCert.NotBefore
	}
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	if notAfter.Before(notBefore) {
		return nil, errors.New("certificate validity window ends before it starts after clamping to the CA")
	}

	t, err := ParseCertType(opts.CertType)
	if err != nil {
		return nil, err
	}
	keyUsage, extKeyUsage, err := certTypeUsage(t)
	if err != nil {
		return nil, err
	}

	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	csrTemplate := &x509.Certificate{
		// SignatureAlgorithm is set below: the CSR's algorithm is kept only
		// when compatible with the CA signing key, so leaves may use a
		// different key algorithm than the CA (e.g. Ed25519 leaf from an
		// RSA CA). The zero value lets x509 pick the signer's default.
		SignatureAlgorithm: signatureAlgorithmForSigner(csr.SignatureAlgorithm, privKey),

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber:          serial,
		Issuer:                caCert.Subject,
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		BasicConstraintsValid: true,
	}

	return x509.CreateCertificate(rand.Reader, csrTemplate, caCert, csrTemplate.PublicKey, privKey)
}

// CASignCSR signs a Certificate Signing Request and returns the certificate
// DER bytes.
//
// certType controls the KeyUsage/ExtKeyUsage of the issued certificate. It
// accepts the same values as ParseCertType (e.g. "server", "client",
// "email", "code-signing"). An empty string uses the historical default
// ("server-client") for backward compatibility.
//
// CACommonName is deprecated and ignored (kept for backward compatibility).
func CASignCSR(CACommonName string, csr *x509.CertificateRequest, caCert *x509.Certificate, privKey crypto.Signer, valid int, certType string) (certDer []byte, err error) {
	return CASignCSRWithOptions(CACommonName, csr, caCert, privKey, SignOptions{ValidDays: valid, CertType: certType})
}

// CASignCSRLegacy preserves the historical behavior of CASignCSR (server+client
// usage). Deprecated: use CASignCSR with an explicit certType.
//
// Deprecated: use CASignCSR with certType="server-client".
func CASignCSRLegacy(CACommonName string, csr *x509.CertificateRequest, caCert *x509.Certificate, privKey crypto.Signer, valid int) ([]byte, error) {
	return CASignCSR(CACommonName, csr, caCert, privKey, valid, string(DefaultCertType))
}

// signatureAlgorithmForSigner returns the CSR's SignatureAlgorithm when it is
// compatible with the CA signing key, otherwise the zero value so that
// x509.CreateCertificate selects the default for the signer's key type. This
// allows signing a CSR whose key algorithm differs from the CA's (e.g. an
// Ed25519 leaf issued by an RSA CA).
func signatureAlgorithmForSigner(csrAlg x509.SignatureAlgorithm, signer crypto.Signer) x509.SignatureAlgorithm {
	switch signer.Public().(type) {
	case *rsa.PublicKey:
		switch csrAlg {
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
			return csrAlg
		}
	case *ecdsa.PublicKey:
		switch csrAlg {
		case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
			return csrAlg
		}
	case ed25519.PublicKey:
		if csrAlg == x509.PureEd25519 {
			return csrAlg
		}
	}
	return x509.UnknownSignatureAlgorithm
}

// RevokeCertificate builds a CRL DER bytes containing the given revoked
// certificates. CACommonName is deprecated and ignored (kept for backward
// compatibility).
func RevokeCertificate(CACommonName string, certificateList []pkix.RevokedCertificate, caCert *x509.Certificate, privKey crypto.Signer) (crlDer []byte, err error) {
	crlNumber, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  caCert.SignatureAlgorithm,
		RevokedCertificates: certificateList,
		Number:              crlNumber,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().AddDate(0, 0, 1),
	}

	return x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, privKey)
}

// ConvertCRLFromDerToPem converts a CRL from DER format to PEM format
func ConvertCRLFromDerToPem(crlDer []byte) (crlPem []byte, err error) {
	var pemCRL = &pem.Block{Type: "X509 CRL", Bytes: crlDer}
	var pemBuff bytes.Buffer

	err = pem.Encode(&pemBuff, pemCRL)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}
