package goca

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"time"

	"github.com/disaster37/goca/cert"
	"github.com/disaster37/goca/key"
	"github.com/pkg/errors"
)

// A Identity represents the Certificate Authority Identity Information
type Identity struct {
	Organization       string   `json:"organization" example:"Company"`                         // Organization name
	OrganizationalUnit string   `json:"organization_unit" example:"Security Management"`        // Organizational Unit name
	Country            string   `json:"country" example:"NL"`                                   // Country (two letters)
	Locality           string   `json:"locality" example:"Noord-Brabant"`                       // Locality name
	Province           string   `json:"province" example:"Veldhoven"`                           // Province name
	EmailAddresses     string   `json:"email" example:"sec@company.com"`                        // Email Address
	DNSNames           []string `json:"dns_names" example:"ca.example.com,root-ca.example.com"` // DNS Names list
	IPAddresses        []net.IP `json:"ip_addresses" example:"10.0.0.1,10.0.0.1"`               // IP addresses list
	Intermediate       bool     `json:"intermediate" example:"false"`                           // Intermediate Certificate Authority (default is false)
	// Type is the certificate type for end-entity certificates issued via
	// IssueCertificate. Accepted values: "server", "client", "server-client",
	// "email", "code-signing", "ocsp-responder", "time-stamping". Empty uses
	// "server-client" (historical default). Ignored when creating a CA.
	Type       string `json:"type" example:"server"`
	KeyBitSize int    `json:"key_size" example:"2048"` // Key Bit Size (default: 2048)
	Valid      int    `json:"valid" example:"365"`     // Minimum 1 day, maximum 3650 days
}

// A CAData represents all the Certificate Authority Data as
// RSA Keys, CRS, CRL, Certificates etc
type CAData struct {
	CRL         string `json:"crl" example:"-----BEGIN X509 CRL-----...-----END X509 CRL-----\n"`               // Revocation List string
	Certificate string `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"` // Certificate string
	//CSR            string `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"` // Certificate Signing Request string
	PrivateKey  string `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"` // Private Key string
	PublicKey   string `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`    // Public Key string
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
	publicKey   *rsa.PublicKey
	//csr            *x509.CertificateRequest
	crl            *x509.RevocationList
	IsIntermediate bool
}

// ErrCAMissingInfo means that all CA Identity fields are required.
var ErrCAMissingInfo = errors.New("all CA details ('Organization', 'Organizational Unit', 'Country', 'Locality', 'Province') are required")

// ErrCertRevoked means the certificate is already on the revocation list.
var ErrCertRevoked = errors.New("the requested Certificate is already revoked")

// ErrParentCANotProvided is returned when creating an intermediate CA without
// a parent certificate or private key.
var ErrParentCANotProvided = errors.New("parent CA certificate or private key is missing when creating an intermediate CA")

// ErrParentNotCA is returned when the parent certificate is not a CA.
var ErrParentNotCA = errors.New("parent certificate is not a CA")

// ErrParentCAExpired is returned when the parent CA certificate has expired.
var ErrParentCAExpired = errors.New("parent CA certificate has expired")

// ErrCertNotIssuedByCA is returned when revoking a certificate that was not
// issued by this CA.
var ErrCertNotIssuedByCA = errors.New("certificate was not issued by this CA")

// ErrCSRSignatureInvalid is returned when a CSR's signature does not verify.
var ErrCSRSignatureInvalid = errors.New("CSR signature verification failed")

// ErrParentCommonNameNotSpecified is kept for backward compatibility.
//
// Deprecated: use ErrParentCANotProvided.
var ErrParentCommonNameNotSpecified = ErrParentCANotProvided

// create creates a new CA or intermediate CA
func (c *CA) create(commonName string, parentCertificate *x509.Certificate, parentPrivateKey *rsa.PrivateKey, id Identity) error {

	caData := CAData{}

	var (
		certBytes []byte
		err       error
	)

	if id.Organization == "" || id.OrganizationalUnit == "" || id.Country == "" || id.Locality == "" || id.Province == "" {
		return ErrCAMissingInfo
	}

	caKeys, err := key.CreateKeys(commonName, commonName, id.KeyBitSize)
	if err != nil {
		return errors.Wrap(err, "failed to create keys")
	}

	privateKeyPem, err := key.ConvertPrivateKeyFromDerToPem(caKeys.Key)
	if err != nil {
		return errors.Wrap(err, "failed to convert private key to PEM")
	}

	publicKeyPem, err := key.ConvertPublicKeyFromDerToPem(caKeys.PublicKey)
	if err != nil {
		return errors.Wrap(err, "failed to convert public key to PEM")
	}

	caData.privateKey = caKeys.Key
	caData.PrivateKey = string(privateKeyPem)
	caData.publicKey = caKeys.PublicKey
	caData.PublicKey = string(publicKeyPem)

	// is not intermediate CA
	if !id.Intermediate {
		caData.IsIntermediate = false
		certBytes, err = cert.CreateRootCert(
			commonName,
			commonName,
			id.Country,
			id.Province,
			id.Locality,
			id.Organization,
			id.OrganizationalUnit,
			id.EmailAddresses,
			id.Valid,
			id.DNSNames,
			id.IPAddresses,
			caKeys.Key,
			caKeys.PublicKey,
		)
	} else {
		// Is intermediate CA
		if parentCertificate == nil || parentPrivateKey == nil {
			return ErrParentCANotProvided
		}
		if !parentCertificate.IsCA {
			return ErrParentNotCA
		}
		if parentCertificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("parent certificate does not have KeyUsageCertSign")
		}
		if time.Now().After(parentCertificate.NotAfter) {
			return ErrParentCAExpired
		}
		caData.IsIntermediate = true

		certBytes, err = cert.CreateCACert(
			commonName,
			commonName,
			id.Country,
			id.Province,
			id.Locality,
			id.Organization,
			id.OrganizationalUnit,
			id.EmailAddresses,
			id.Valid,
			id.DNSNames,
			id.IPAddresses,
			caKeys.Key,
			parentPrivateKey,
			parentCertificate,
			caKeys.PublicKey,
		)
	}
	if err != nil {
		return errors.Wrap(err, "failed to create CA certificate")
	}
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse CA certificate")
	}
	caData.certificate = certificate

	crtPem, err := cert.ConvertCertificateFromDerToPem(certBytes)
	if err != nil {
		return errors.Wrap(err, "failed to convert CA certificate to PEM")
	}
	caData.Certificate = string(crtPem)

	crlBytes, err := cert.RevokeCertificate(c.CommonName, []pkix.RevokedCertificate{}, certificate, caKeys.Key)
	if err != nil {
		return errors.Wrap(err, "failed to create CRL")
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse CRL")
	}
	caData.crl = crl

	crlPem, err := cert.ConvertCRLFromDerToPem(crlBytes)
	if err != nil {
		return errors.Wrap(err, "failed to convert CRL to PEM")
	}
	caData.CRL = string(crlPem)

	c.Data = caData

	return nil
}

// LoadCA loads an existing CA from its PEM-encoded components.
func (c *CA) LoadCA(privateKeyPem []byte, publicKeyPem []byte, certPem []byte, crlPem []byte) error {
	if len(privateKeyPem) == 0 {
		return errors.New("private key must be provided")
	}
	if len(publicKeyPem) == 0 {
		return errors.New("public key must be provided")
	}
	if len(certPem) == 0 {
		return errors.New("certificate must be provided")
	}
	if len(crlPem) == 0 {
		return errors.New("CRL must be provided")
	}

	caData := CAData{
		PrivateKey:  string(privateKeyPem),
		PublicKey:   string(publicKeyPem),
		Certificate: string(certPem),
		CRL:         string(crlPem),
	}

	privateKey, err := key.LoadPrivateKeyFromPem(privateKeyPem)
	if err != nil {
		return errors.Wrap(err, "failed to load private key")
	}
	caData.privateKey = privateKey

	publicKey, err := key.LoadPublicKeyFromPem(publicKeyPem)
	if err != nil {
		return errors.Wrap(err, "failed to load public key")
	}
	caData.publicKey = publicKey

	crt, err := cert.LoadCertFromPem(certPem)
	if err != nil {
		return errors.Wrap(err, "failed to load certificate")
	}
	caData.certificate = crt

	crl, err := cert.LoadCRLFromPem(crlPem)
	if err != nil {
		return errors.Wrap(err, "failed to load CRL")
	}
	caData.crl = crl

	c.Data = caData
	c.CommonName = caData.certificate.Subject.CommonName

	return nil
}

// signCSR generates a certificate from a CSR.
// certType controls the KeyUsage/ExtKeyUsage (see cert.ParseCertType).
func (c *CA) signCSR(csr *x509.CertificateRequest, valid int, certType string) (certificate *Certificate, err error) {
	// Verify the CSR signature before signing.
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.Wrap(ErrCSRSignatureInvalid, err.Error())
	}

	certificate = &Certificate{
		commonName:    csr.Subject.CommonName,
		csr:           csr,
		caCertificate: c.Data.certificate,
		CACertificate: c.Data.Certificate,
		certType:      certType,
	}

	csrDer, err := asn1.Marshal(csr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CSR")
	}
	csrPem, err := cert.ConvertCSRFromDerToPem(csrDer)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert CSR to PEM")
	}
	certificate.CSR = string(csrPem)

	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, c.Data.privateKey, valid, certType)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign CSR")
	}

	crt, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse signed certificate")
	}
	certificate.certificate = crt

	crtPem, err := cert.ConvertCertificateFromDerToPem(certBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert certificate to PEM")
	}
	certificate.Certificate = string(crtPem)

	return certificate, nil
}

// issueCertificate permit to generate new certificate signed by CA
func (c *CA) issueCertificate(commonName string, id Identity) (certificate *Certificate, err error) {
	certificate = &Certificate{
		caCertificate: c.Data.certificate,
		CACertificate: c.Data.Certificate,
		certType:      id.Type,
	}

	certKeys, err := key.CreateKeys(c.CommonName, commonName, id.KeyBitSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create certificate keys")
	}

	privateKeyPem, err := key.ConvertPrivateKeyFromDerToPem(certKeys.Key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert private key to PEM")
	}

	rsaPrivateKeyPem, err := key.ConvertRsaPrivateKeyFromDerToPem(certKeys.Key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert RSA private key to PEM")
	}

	publicKeyPem, err := key.ConvertPublicKeyFromDerToPem(certKeys.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert public key to PEM")
	}

	certificate.privateKey = certKeys.Key
	certificate.PrivateKey = string(privateKeyPem)
	certificate.RsaPrivateKey = string(rsaPrivateKeyPem)
	certificate.publicKey = certKeys.PublicKey
	certificate.PublicKey = string(publicKeyPem)

	csrBytes, err := cert.CreateCSR(c.CommonName, commonName, id.Country, id.Province, id.Locality, id.Organization, id.OrganizationalUnit, id.EmailAddresses, id.DNSNames, id.IPAddresses, certKeys.Key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create CSR")
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CSR")
	}
	csrPem, err := cert.ConvertCSRFromDerToPem(csrBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert CSR to PEM")
	}

	certificate.csr = csr
	certificate.CSR = string(csrPem)
	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, c.Data.privateKey, id.Valid, id.Type)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign CSR")
	}

	crt, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}
	certificate.certificate = crt

	certificatePem, err := cert.ConvertCertificateFromDerToPem(certBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert certificate to PEM")
	}
	certificate.Certificate = string(certificatePem)

	return certificate, nil
}

// revokeCertificate adds a certificate to the CRL.
func (c *CA) revokeCertificate(certificate *x509.Certificate) error {
	if certificate == nil {
		return errors.New("certificate is nil")
	}
	// Verify the certificate was issued by this CA.
	if !bytes.Equal(certificate.RawIssuer, c.Data.certificate.RawSubject) {
		return ErrCertNotIssuedByCA
	}

	var revokedCerts []pkix.RevokedCertificate

	currentCRL := c.GoCRL()
	if currentCRL != nil && len(currentCRL.RevokedCertificates) > 0 {
		for _, revoked := range currentCRL.RevokedCertificates {
			if revoked.SerialNumber.String() == certificate.SerialNumber.String() {
				return ErrCertRevoked
			}
		}
		revokedCerts = currentCRL.RevokedCertificates
	}

	newCertRevoke := pkix.RevokedCertificate{
		SerialNumber:   certificate.SerialNumber,
		RevocationTime: time.Now(),
	}

	revokedCerts = append(revokedCerts, newCertRevoke)

	crlByte, err := cert.RevokeCertificate(c.CommonName, revokedCerts, c.Data.certificate, c.Data.privateKey)
	if err != nil {
		return errors.Wrap(err, "failed to generate CRL")
	}

	crl, err := x509.ParseRevocationList(crlByte)
	if err != nil {
		return errors.Wrap(err, "failed to parse CRL")
	}
	c.Data.crl = crl

	crlPem, err := cert.ConvertCRLFromDerToPem(crlByte)
	if err != nil {
		return errors.Wrap(err, "failed to convert CRL to PEM")
	}
	c.Data.CRL = string(crlPem)

	return nil
}
