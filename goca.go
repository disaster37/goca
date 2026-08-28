// Package goca provides Certificate Authority (CA) framework for Go.
//
// GoCA is a pure library on top of crypto/x509 to manage Certificate
// Authorities, issue certificates, sign Certificate Signing Requests (CSR),
// revoke certificates (CRL), and export PKCS#12 bundles.
//
// GoCA does not touch the filesystem. The caller is responsible for
// persisting and loading PEM-encoded keys, certificates, and CRLs.
package goca

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"

	"github.com/pkg/errors"
	"software.sslmate.com/src/go-pkcs12"
)

// CA represents the basic CA data
type CA struct {
	CommonName string // Certificate Authority Common Name
	Data       CAData // Certificate Authority Data (CAData{})
}

// Certificate represents a Certificate data
type Certificate struct {
	commonName    string                   // Certificate Common Name
	Certificate   string                   `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`             // Certificate certificate string
	CSR           string                   `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"`     // Certificate Signing Request string
	RsaPrivateKey string                   `json:"rsa_private_key" example:"-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----\n"` // Certificate Private Key string
	PrivateKey    string                   `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"`             // Certificate Private Key string
	PublicKey     string                   `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`                // Certificate Public Key string
	CACertificate string                   `json:"ca_certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`          // CA Certificate as string
	privateKey    crypto.Signer            // Certificate Private Key object crypto.Signer (RSA, ECDSA, or Ed25519)
	publicKey     crypto.PublicKey         // Certificate Public Key object crypto.PublicKey
	csr           *x509.CertificateRequest // Certificate Sigining Request object x509.CertificateRequest
	certificate   *x509.Certificate        // Certificate certificate *x509.Certificate
	caCertificate *x509.Certificate        // CA Certificate *x509.Certificate
	certType      string
}

//
// Certificate Authority
//

// New creates a new Root Certificate Authority
func New(commonName string, identity Identity) (ca *CA, err error) {
	ca, err = NewCA(commonName, nil, nil, identity)
	return ca, err
}

// NewCA creates a new Root or Intermediate Certificate Authority
func NewCA(commonName string, parentCertificate *x509.Certificate, parentPrivateKey crypto.Signer, identity Identity) (ca *CA, err error) {
	ca = &CA{
		CommonName: commonName,
	}

	err = ca.create(commonName, parentCertificate, parentPrivateKey, identity)
	if err != nil {
		return nil, err
	}

	return ca, nil
}

// GetPublicKey returns the PublicKey as string
func (c *CA) GetPublicKey() string {
	return c.Data.PublicKey
}

// GetPrivateKey returns the Private Key as string
func (c *CA) GetPrivateKey() string {
	return c.Data.PrivateKey
}

// GoPrivateKey returns the Private Key as *rsa.PrivateKey.
// Returns nil when the CA key is not RSA. Prefer GoSigner for new code.
func (c *CA) GoPrivateKey() *rsa.PrivateKey {
	if k, ok := c.Data.privateKey.(*rsa.PrivateKey); ok {
		return k
	}
	return nil
}

// GoPublicKey returns the Public Key as *rsa.PublicKey.
// Returns nil when the CA key is not RSA. Prefer GoPublic for new code.
func (c *CA) GoPublicKey() *rsa.PublicKey {
	if k, ok := c.Data.publicKey.(*rsa.PublicKey); ok {
		return k
	}
	return nil
}

// GoSigner returns the CA private key as a crypto.Signer (RSA, ECDSA, or
// Ed25519). Prefer this over GoPrivateKey for new code.
func (c *CA) GoSigner() crypto.Signer { return c.Data.privateKey }

// GoPublic returns the CA public key as a crypto.PublicKey.
func (c *CA) GoPublic() crypto.PublicKey { return c.Data.publicKey }

// GetCertificate returns Certificate Authority Certificate as string
func (c *CA) GetCertificate() string {
	return c.Data.Certificate
}

// GoCertificate returns Certificate Authority Certificate as Go bytes *x509.Certificate
func (c *CA) GoCertificate() *x509.Certificate {
	return c.Data.certificate
}

// GetCRL returns Certificate Revocation List as x509 CRL string
func (c *CA) GetCRL() string {
	return c.Data.CRL
}

// GoCRL returns the Certificate Revocation List as *x509.RevocationList.
func (c *CA) GoCRL() *x509.RevocationList {
	return c.Data.crl
}

// IsIntermediate returns if the CA is Intermediate CA (true)
func (c *CA) IsIntermediate() bool {
	return c.Data.IsIntermediate

}

// Status get details about Certificate Authority status.
func (c *CA) Status() string {
	if c.Data.IsIntermediate && c.Data.Certificate == "" {
		return "Intermediate Certificate Authority not ready, missing Certificate."

	} else if c.Data.IsIntermediate && c.Data.Certificate != "" {
		return "Intermediate Certificate Authority is ready."

	} else if !c.Data.IsIntermediate && c.Data.Certificate != "" {
		return "Certificate Authority is ready."

	} else {
		return "CA is inconsistent."
	}
}

// SignCSR creates a certificate from a CSR (x509.CertificateRequest).
//
// Deprecated: use SignCSRWithType, which lets you choose the certificate type.
// This overload uses the historical default type ("server-client").
func (c *CA) SignCSR(csr *x509.CertificateRequest, valid int) (certificate *Certificate, err error) {
	return c.SignCSRWithType(csr, valid, "")
}

// SignCSRWithType creates a certificate from a CSR with an explicit
// certificate type. certType accepts the values documented on
// cert.ParseCertType (e.g. "server", "client", "email"). An empty string uses
// the historical default.
func (c *CA) SignCSRWithType(csr *x509.CertificateRequest, valid int, certType string) (certificate *Certificate, err error) {
	return c.signCSR(csr, valid, certType)
}

// IssueCertificate creates a new certificate
//
// It is import create an Identity{} with Certificate Client/Server information.
func (c *CA) IssueCertificate(commonName string, id Identity) (certificate *Certificate, err error) {

	certificate, err = c.issueCertificate(commonName, id)

	return certificate, err
}

// RevokeCertificate revokes a certificate managed by the Certificate Authority
func (c *CA) RevokeCertificate(certificate *x509.Certificate) error {
	return c.revokeCertificate(certificate)
}

//
// Certificates
//

// GetCertificate returns the certificate as string.
func (c *Certificate) GetCertificate() string {
	return c.Certificate
}

// GoCert returns the certificate as Go x509.Certificate.
func (c *Certificate) GoCert() *x509.Certificate {
	return c.certificate
}

// GetCSR returns the certificate as string.
func (c *Certificate) GetCSR() string {
	return c.CSR
}

// GoCSR returns the certificate as Go x509.Certificate.
func (c *Certificate) GoCSR() *x509.CertificateRequest {
	return c.csr
}

// GetCACertificate returns the certificate as string.
func (c *Certificate) GetCACertificate() string {
	return c.CACertificate
}

// GoCACertificate returns the certificate *x509.Certificate.
func (c *Certificate) GoCACertificate() *x509.Certificate {
	return c.caCertificate
}

// Type returns the certificate type string (e.g. "server", "client").
// Returns "" for certificates created before the Type field existed.
func (c *Certificate) Type() string {
	return c.certType
}

// GeneratePKCS12 encodes a Certificate (with its CA chain) into a PKCS#12
// bundle using the modern 2023 encryption profile (PBES2/AES-256-CBC +
// HMAC-SHA-256). The passphrase must be non-empty.
func GeneratePKCS12(certificate *Certificate, passphrase string, otherCaCerts ...*x509.Certificate) (pfxData []byte, err error) {
	if certificate == nil {
		return nil, errors.New("certificate is nil")
	}
	if certificate.privateKey == nil || certificate.certificate == nil {
		return nil, errors.New("certificate is missing its private key or certificate")
	}
	if passphrase == "" {
		return nil, errors.New("passphrase is required for PKCS#12 encoding")
	}

	cas := []*x509.Certificate{certificate.caCertificate}
	if len(otherCaCerts) > 0 {
		cas = append(cas, otherCaCerts...)
	}

	encoder := pkcs12.Modern2023
	return encoder.Encode(certificate.privateKey, certificate.certificate, cas, passphrase)
}

// GeneratePkcs12 is kept for backward compatibility.
//
// Deprecated: use GeneratePKCS12, which uses modern PKCS#12 encryption.
func GeneratePkcs12(certificate *Certificate, passphrase string, otherCaCerts ...*x509.Certificate) (pfxData []byte, err error) {
	return GeneratePKCS12(certificate, passphrase, otherCaCerts...)
}
