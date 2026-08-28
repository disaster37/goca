package goca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rootCAIdentity() Identity {
	return Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
	}
}

// TestIssueECDSA creates an ECDSA CA and issues an ECDSA leaf.
func TestIssueECDSA(t *testing.T) {
	rootCA, err := New("go-root.ca", Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		KeyAlgorithm:       "ecdsa-p256",
	})
	require.NoError(t, err)
	require.NotNil(t, rootCA)

	cert, err := rootCA.IssueCertificate("leaf.go-root.ca", Identity{
		Organization: "GO CA Root Company Inc.",
		KeyAlgorithm: "ecdsa-p256",
		Type:         "server-client",
	})
	require.NoError(t, err)
	require.NotNil(t, cert)

	assert.Equal(t, x509.ECDSA, cert.GoCert().PublicKeyAlgorithm)
	_, ok := rootCA.GoSigner().(*ecdsa.PrivateKey)
	assert.True(t, ok, "CA signer must be *ecdsa.PrivateKey")
	assert.Nil(t, rootCA.GoPrivateKey())
	assert.NotEmpty(t, cert.PrivateKey)
	assert.Empty(t, cert.RsaPrivateKey)
}

// TestIssueSubDayValidity issues a certificate with a 2-hour validity.
func TestIssueSubDayValidity(t *testing.T) {
	rootCA, err := New("go-root.ca", rootCAIdentity())
	require.NoError(t, err)

	before := time.Now()
	cert, err := rootCA.IssueCertificate("leaf.go-root.ca", Identity{
		Organization:  "GO CA Root Company Inc.",
		Type:          "client",
		ValidDuration: 2 * time.Hour,
	})
	require.NoError(t, err)
	after := time.Now()

	expected := before.Add(2 * time.Hour)
	assert.WithinDuration(t, expected, cert.GoCert().NotAfter, 2*time.Minute+after.Sub(before))
	assert.True(t, cert.GoCert().NotAfter.Before(after.Add(2*time.Hour+2*time.Minute)))
	assert.True(t, cert.GoCert().NotAfter.After(before.Add(2*time.Hour-2*time.Minute)))
}

// TestIssueBackdate issues a certificate backdated by 5 minutes.
func TestIssueBackdate(t *testing.T) {
	rootCA, err := New("go-root.ca", rootCAIdentity())
	require.NoError(t, err)

	before := time.Now()
	cert, err := rootCA.IssueCertificate("leaf.go-root.ca", Identity{
		Organization: "GO CA Root Company Inc.",
		Type:         "server-client",
		Backdate:     5 * time.Minute,
	})
	require.NoError(t, err)
	after := time.Now()

	assert.True(t, cert.GoCert().NotBefore.Before(before.Add(-5*time.Minute+2*time.Minute)))
	assert.True(t, cert.GoCert().NotBefore.After(after.Add(-5*time.Minute-2*time.Minute)))
	assert.False(t, cert.GoCert().NotBefore.Before(rootCA.GoCertificate().NotBefore))
}

// TestLoadCAFromPEM loads a CA from cert+key PEM only and issues a leaf.
func TestLoadCAFromPEM(t *testing.T) {
	rootCA, err := New("go-root.ca", rootCAIdentity())
	require.NoError(t, err)

	loaded := &CA{}
	err = loaded.LoadCAFromPEM([]byte(rootCA.GetCertificate()), []byte(rootCA.GetPrivateKey()))
	require.NoError(t, err)

	assert.Equal(t, rootCA.GetCertificate(), loaded.GetCertificate())
	assert.NotEmpty(t, loaded.GetCRL())
	assert.NotNil(t, loaded.GoSigner())
	assert.NotEmpty(t, loaded.GetPublicKey())

	cert, err := loaded.IssueCertificate("leaf.go-root.ca", Identity{
		Organization: "GO CA Root Company Inc.",
		Type:         "server-client",
	})
	require.NoError(t, err)

	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM([]byte(loaded.GetCertificate()))
	require.True(t, ok)

	_, err = cert.GoCert().Verify(x509.VerifyOptions{Roots: pool})
	require.NoError(t, err)
}

// TestLeafNotAfterClampedToCA verifies leaf validity is clamped to the CA's.
func TestLeafNotAfterClampedToCA(t *testing.T) {
	rootCA, err := New("go-root.ca", Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Valid:              1,
	})
	require.NoError(t, err)

	cert, err := rootCA.IssueCertificate("leaf.go-root.ca", Identity{
		Organization: "GO CA Root Company Inc.",
		Type:         "server",
		Valid:        3650,
	})
	require.NoError(t, err)

	assert.WithinDuration(t, rootCA.GoCertificate().NotAfter, cert.GoCert().NotAfter, time.Second)
}

// TestUnknownKeyAlgorithm verifies unknown key algorithms are rejected.
func TestUnknownKeyAlgorithm(t *testing.T) {
	_, err := New("go-root.ca", Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		KeyAlgorithm:       "bogus",
	})
	require.Error(t, err)
}

// TestEd25519RoundTrip issues an Ed25519 leaf from an RSA CA.
func TestEd25519RoundTrip(t *testing.T) {
	rootCA, err := New("go-root.ca", rootCAIdentity())
	require.NoError(t, err)

	cert, err := rootCA.IssueCertificate("leaf.go-root.ca", Identity{
		Organization: "GO CA Root Company Inc.",
		KeyAlgorithm: "ed25519",
		Type:         "client",
	})
	require.NoError(t, err)

	assert.Equal(t, x509.Ed25519, cert.GoCert().PublicKeyAlgorithm)
	assert.NotNil(t, cert.GoCert())
	assert.Empty(t, cert.RsaPrivateKey)
	assert.NotEmpty(t, cert.PrivateKey)
}
