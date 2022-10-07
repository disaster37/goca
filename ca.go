package goca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"time"

	"github.com/disaster37/goca/cert"
	"github.com/disaster37/goca/key"
	"github.com/pkg/errors"
	"software.sslmate.com/src/go-pkcs12" 
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
	IPAddresses				 []net.IP `json:"ip_addresses" example:"10.0.0.1,10.0.0.1"` 							// IP addresses list
 	Intermediate       bool     `json:"intermediate" example:"false"`                           // Intermendiate Certificate Authority (default is false)
	KeyBitSize         int      `json:"key_size" example:"2048"`                                // Key Bit Size (defaul: 2048)
	Valid              int      `json:"valid" example:"365"`                                    // Minimum 1 day, maximum 825 days -- Default: 397
}

// A CAData represents all the Certificate Authority Data as
// RSA Keys, CRS, CRL, Certificates etc
type CAData struct {
	CRL            string `json:"crl" example:"-----BEGIN X509 CRL-----...-----END X509 CRL-----\n"`                       // Revocation List string
	Certificate    string `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`         // Certificate string
	//CSR            string `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"` // Certificate Signing Request string
	PrivateKey     string `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"`         // Private Key string
	PublicKey      string `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`            // Public Key string
	privateKey     *rsa.PrivateKey
	certificate    *x509.Certificate
	publicKey      *rsa.PublicKey
	//csr            *x509.CertificateRequest
	crl            *pkix.CertificateList
	IsIntermediate bool
}

// ErrCAMissingInfo means that all information goca.Information{} is required
var ErrCAMissingInfo = errors.New("all CA details ('Organization', 'Organizational Unit', 'Country', 'Locality', 'Province') are required")

// ErrCertRevoked means that certificate was not found in $CAPATH to be loaded.
var ErrCertRevoked = errors.New("the requested Certificate is already revoked")

var ErrParentCommonNameNotSpecified = errors.New("parent common name is empty when creating an intermediate CA certificate")

// create permit to create new CA or intermediate CA
func (c *CA) create(commonName string, parentCertificate *x509.Certificate, parentPrivateKey *rsa.PrivateKey, id Identity) error {

	caData := CAData{}

	var (
		certBytes       []byte
		err             error
	)

	if id.Organization == "" || id.OrganizationalUnit == "" || id.Country == "" || id.Locality == "" || id.Province == "" {
		return ErrCAMissingInfo
	}


	caKeys, err := key.CreateKeys(commonName, commonName, id.KeyBitSize)
	if err != nil {
		return errors.Wrap(err, "Error when create keys")
	}

	privateKeyPem, err := key.ConvertPrivateKeyFromDerToPem(caKeys.Key)
	if err != nil {
		return errors.Wrap(err, "Error when convert private key to PEM")
	}

	publicKeyPem, err := key.ConvertPublicKeyFromDerToPem(caKeys.PublicKey)
	if err != nil {
		return errors.Wrap(err, "Error when convert public key to PEM")
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
			return ErrParentCommonNameNotSpecified
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
		return errors.Wrap(err, "Error when create CA certificate")
	}
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return errors.Wrap(err, "Error parse CA certificate")
	}
	caData.certificate = certificate

	crtPem, err := cert.ConvertCertificateFromDerToPem(certBytes)
	if err != nil {
		return errors.Wrap(err, "Error when convert CA certificate to PEM")
	}
	caData.Certificate = string(crtPem)
	
	crlBytes, err := cert.RevokeCertificate(c.CommonName, []pkix.RevokedCertificate{}, certificate, caKeys.Key)
	if err != nil {
		return errors.Wrap(err, "Error when create CRL")
	}
	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		return errors.Wrap(err, "Error when parse CRL")
	}
	caData.crl = crl

	crlPem, err := cert.ConvertCRLFromDerToPem(crlBytes)
	if err != nil {
		return errors.Wrap(err, "Error when convert CRL to PEM")
	}
	caData.CRL = string(crlPem)

	c.Data = caData

	return nil
}

// loadCA permti to load existing CA
func (c *CA) LoadCA(privateKeyPem []byte, publicKeyPem []byte, certPem []byte, crlPem []byte) error {

	if len(privateKeyPem) == 0 {
		return errors.New("Private key must be provided")
	}
	if len(publicKeyPem) == 0 {
		return errors.New("Public key must be provided")
	}
	if len(certPem) == 0 {
		return errors.New("Certificate must be provided")
	}

	caData := CAData{
		PrivateKey: string(privateKeyPem),
		PublicKey: string(publicKeyPem),
		Certificate: string(certPem),
		CRL: string(crlPem),
	}

	privateKey, err := key.LoadPrivateKeyFromPem(privateKeyPem)
	if err != nil {
		return err
	}
	caData.privateKey = privateKey

	publicKey, err := key.LoadPublicKeyFromPem(publicKeyPem)
	if err != nil {
		return err
	}
	caData.publicKey = publicKey

	crt, err := cert.LoadCertFromPem(certPem)
	if err != nil {
		return err
	}
	caData.certificate = crt

	crl, err := cert.LoadCRLFromPem(crlPem)
	if err != nil {
		return err
	}
	caData.crl = crl
	
	c.Data = caData

	return nil
}

// signCSR permit to generate certificate from CSR
func (c *CA) signCSR(csr *x509.CertificateRequest, valid int) (certificate *Certificate, err error) {

	certificate = &Certificate{
		commonName:    csr.Subject.CommonName,
		csr:           csr,
		caCertificate: c.Data.certificate,
		CACertificate: c.Data.Certificate,
	}

	csrDer, err := asn1.Marshal(csr)
	if err != nil {
			return nil, err
	}
	csrPem, err := cert.ConvertCSRFromDerToPem(csrDer)
	if err != nil {
		return nil, err
	}
	certificate.CSR = string(csrPem)

	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, c.Data.privateKey, valid)
	if err != nil {
		return certificate, err
	}

	crt, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	certificate.certificate = crt

	crtPem, err := cert.ConvertCertificateFromDerToPem(certBytes)
	if err != nil {
		return nil, err
	}
	certificate.Certificate = string(crtPem)

	return certificate, err
}

// issueCertificate permit to generate new certificate signed by CA
func (c *CA) issueCertificate(commonName string, id Identity) (certificate *Certificate, err error) {

	certificate = &Certificate{
		caCertificate: c.Data.certificate,
		CACertificate: c.Data.Certificate,
	} 

	certKeys, err := key.CreateKeys(c.CommonName, commonName, id.KeyBitSize)
	if err != nil {
		return nil, err
	}

	privateKeyPem, err := key.ConvertPrivateKeyFromDerToPem(certKeys.Key)
	if err != nil {
		return nil, err
	}

	publicKeyPem, err := key.ConvertPublicKeyFromDerToPem(certKeys.PublicKey)
	if err != nil {
		return nil, err
	}


	certificate.privateKey = certKeys.Key
	certificate.PrivateKey = string(privateKeyPem)
	certificate.publicKey = certKeys.PublicKey
	certificate.PublicKey = string(publicKeyPem)

	csrBytes, err := cert.CreateCSR(c.CommonName, commonName, id.Country, id.Province, id.Locality, id.Organization, id.OrganizationalUnit, id.EmailAddresses, id.DNSNames, id.IPAddresses, certKeys.Key)
	if err != nil {
		return nil, err
	}

	csr, _ := x509.ParseCertificateRequest(csrBytes)
	csrPem, err := cert.ConvertCSRFromDerToPem(csrBytes)
	if err != nil {
		return nil, err
	}

	certificate.csr = csr
	certificate.CSR = string(csrPem)
	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, c.Data.privateKey, id.Valid)
	if err != nil {
		return nil, err
	}

	crt, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	certificate.certificate = crt

	certificatePem, err := cert.ConvertCertificateFromDerToPem(certBytes)
	if err != nil {
		return nil, err
	}
	certificate.Certificate = string(certificatePem)

	pkcs12, err := pkcs12.Encode(rand.Reader, certKeys.Key, crt, []*x509.Certificate{certificate.caCertificate}, "")
	if err != nil {
		return nil, err
	}
	certificate.Pkcs12 = pkcs12

	return certificate, nil

}

// revokeCertificate permit to revoke certificate
// It add it on  rovokated list
func (c *CA) revokeCertificate(certificate *x509.Certificate) error {

	var revokedCerts []pkix.RevokedCertificate

	currentCRL := c.GoCRL()
	if currentCRL != nil {
		for _, serialNumber := range currentCRL.TBSCertList.RevokedCertificates {
			if serialNumber.SerialNumber.String() == certificate.SerialNumber.String() {
				return ErrCertRevoked
			}
		}

		revokedCerts = currentCRL.TBSCertList.RevokedCertificates
	}

	newCertRevoke := pkix.RevokedCertificate{
		SerialNumber:   certificate.SerialNumber,
		RevocationTime: time.Now(),
	}

	revokedCerts = append(revokedCerts, newCertRevoke)

	crlByte, err := cert.RevokeCertificate(c.CommonName, revokedCerts, c.Data.certificate, c.Data.privateKey)
	if err != nil {
		return err
	}

	crl, err := x509.ParseCRL(crlByte)
	if err != nil {
		return err
	}
	c.Data.crl = crl

	crlPem, err := cert.ConvertCRLFromDerToPem(crlByte)
	if err != nil {
		return err
	}
	c.Data.CRL = string(crlPem)

	return nil
}
