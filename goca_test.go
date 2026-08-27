package goca

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFunctionalRootCACreation creates a RootCA.
func TestFunctionalRootCACreation(t *testing.T) {
	rootCAIdentity := Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
		DNSNames:           []string{"www.go-root.ca", "secure.go-root.ca"},
	}

	rootCompanyCA, err := New("go-root.ca", rootCAIdentity)
	require.NoError(t, err)
	require.NotNil(t, rootCompanyCA)
	assert.False(t, rootCompanyCA.IsIntermediate())
	assert.Equal(t, "Certificate Authority is ready.", rootCompanyCA.Status())
	assert.NotEmpty(t, rootCompanyCA.GetCertificate())
	assert.NotEmpty(t, rootCompanyCA.GetPrivateKey())
	assert.NotEmpty(t, rootCompanyCA.GetPublicKey())
	assert.NotEmpty(t, rootCompanyCA.GetCRL())
}

// TestFunctionalIntermediateCACreation creates an intermediate CA.
func TestFunctionalIntermediateCACreation(t *testing.T) {
	rootCAIdentity := Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
		DNSNames:           []string{"www.go-root.ca", "secure.go-root.ca"},
	}
	rootCompanyCA, err := New("go-root.ca", rootCAIdentity)
	require.NoError(t, err)

	intermediateCAIdentity := Identity{
		Organization:       "Intermediate CA Company Inc.",
		OrganizationalUnit: "Intermediate Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       true,
	}

	intermediateCA, err := NewCA("go-intermediate.ca", rootCompanyCA.GoCertificate(), rootCompanyCA.GoPrivateKey(), intermediateCAIdentity)
	require.NoError(t, err)
	require.NotNil(t, intermediateCA)
	assert.True(t, intermediateCA.IsIntermediate())
	assert.NotEmpty(t, intermediateCA.GetCertificate())
	assert.NotEmpty(t, intermediateCA.GetPrivateKey())
	assert.NotEmpty(t, intermediateCA.GetPublicKey())
	assert.NotEmpty(t, intermediateCA.GetCRL())
}

// TestFunctionalRootCAIssueNewCertificate issues a certificate and checks its
// type matches the requested Type.
func TestFunctionalRootCAIssueNewCertificate(t *testing.T) {
	rootCAIdentity := Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
		DNSNames:           []string{"www.go-root.ca", "secure.go-root.ca"},
	}
	rootCA, err := New("go-root.ca", rootCAIdentity)
	require.NoError(t, err)

	intranetIdentity := Identity{
		Organization:       "SFTP Server CA Company Inc.",
		OrganizationalUnit: "Intermediate Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		DNSNames:           []string{"w3.intranet.go-root.ca"},
		Type:               "server",
	}

	cert, err := rootCA.IssueCertificate("intranet.go-root.ca", intranetIdentity)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.GetCACertificate())
	assert.NotEmpty(t, cert.GetCertificate())
	assert.NotEmpty(t, cert.GetCSR())
	assert.NotEmpty(t, cert.PrivateKey)
	assert.Equal(t, "server", cert.Type())

	// Verify the KeyUsage matches the server type.
	assert.Contains(t, cert.GoCert().ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.NotContains(t, cert.GoCert().ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

// TestFunctionalRootCALoadCA loads a CA from its PEM components.
func TestFunctionalRootCALoadCA(t *testing.T) {
	rootCAIdentity := Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
		DNSNames:           []string{"www.go-root.ca"},
	}
	rootCA, err := New("go-root.ca", rootCAIdentity)
	require.NoError(t, err)

	loaded := &CA{}
	err = loaded.LoadCA(
		[]byte(rootCA.GetPrivateKey()),
		[]byte(rootCA.GetPublicKey()),
		[]byte(rootCA.GetCertificate()),
		[]byte(rootCA.GetCRL()),
	)
	require.NoError(t, err)
	assert.Equal(t, rootCA.GetCertificate(), loaded.GetCertificate())
	assert.Equal(t, rootCA.GetCRL(), loaded.GetCRL())
}

// TestFunctionalRevokeCertificate issues a cert, revokes it, and verifies the
// CRL contains the serial number.
func TestFunctionalRevokeCertificate(t *testing.T) {
	rootCAIdentity := Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
		DNSNames:           []string{"www.go-root.ca"},
	}
	rootCA, err := New("go-root.ca", rootCAIdentity)
	require.NoError(t, err)

	cert, err := rootCA.IssueCertificate("intranet.go-root.ca", Identity{
		Organization: "O", OrganizationalUnit: "U", Country: "NL",
		Locality: "L", Province: "P", Type: "server",
	})
	require.NoError(t, err)

	err = rootCA.RevokeCertificate(cert.GoCert())
	require.NoError(t, err)

	crl := rootCA.GoCRL()
	require.NotNil(t, crl)
	require.NotEmpty(t, crl.RevokedCertificates)
	assert.Equal(t, 0, cert.GoCert().SerialNumber.Cmp(crl.RevokedCertificates[0].SerialNumber))

	// Revoking twice must fail.
	err = rootCA.RevokeCertificate(cert.GoCert())
	assert.ErrorIs(t, err, ErrCertRevoked)
}

// TestFunctionalRevokeCertificate_NotIssued verifies that revoking a cert from
// another CA fails.
func TestFunctionalRevokeCertificate_NotIssued(t *testing.T) {
	id := Identity{
		Organization: "O", OrganizationalUnit: "U", Country: "NL",
		Locality: "L", Province: "P",
	}
	caA, err := New("a.ca", id)
	require.NoError(t, err)
	caB, err := New("b.ca", id)
	require.NoError(t, err)

	certA, err := caA.IssueCertificate("client.a.ca", Identity{
		Organization: "O", OrganizationalUnit: "U", Country: "NL",
		Locality: "L", Province: "P", Type: "client",
	})
	require.NoError(t, err)

	err = caB.RevokeCertificate(certA.GoCert())
	assert.ErrorIs(t, err, ErrCertNotIssuedByCA)
}

// TestGeneratePKCS12 encodes a certificate and decodes it back.
func TestGeneratePKCS12(t *testing.T) {
	rootCA, err := New("go-root.ca", Identity{
		Organization: "O", OrganizationalUnit: "U", Country: "NL",
		Locality: "L", Province: "P",
	})
	require.NoError(t, err)

	cert, err := rootCA.IssueCertificate("client.go-root.ca", Identity{
		Organization: "O", OrganizationalUnit: "U", Country: "NL",
		Locality: "L", Province: "P", Type: "client",
	})
	require.NoError(t, err)

	pfx, err := GeneratePKCS12(cert, "passphrase123")
	require.NoError(t, err)
	assert.NotEmpty(t, pfx)
	// PKCS#12 PFX data starts with ASN.1 SEQUENCE (0x30).
	assert.True(t, len(pfx) > 0 && pfx[0] == 0x30, "PFX must start with ASN.1 SEQUENCE")
}

func TestGeneratePKCS12_EmptyPassphrase(t *testing.T) {
	rootCA, err := New("go-root.ca", Identity{
		Organization: "O", OrganizationalUnit: "U", Country: "NL",
		Locality: "L", Province: "P",
	})
	require.NoError(t, err)
	cert, err := rootCA.IssueCertificate("c.go-root.ca", Identity{
		Organization: "O", OrganizationalUnit: "U", Country: "NL",
		Locality: "L", Province: "P", Type: "client",
	})
	require.NoError(t, err)
	_, err = GeneratePKCS12(cert, "")
	assert.Error(t, err)
}
