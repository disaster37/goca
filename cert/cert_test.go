package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return k
}

// ---- newSerialNumber ----

func TestNewSerialNumber(t *testing.T) {
	n, err := newSerialNumber()
	require.NoError(t, err)
	assert.True(t, n.Sign() > 0)
}

// ---- CreateCSR ----

func TestCreateCSR(t *testing.T) {
	priv := testKey(t, 2048)
	dns := []string{"a.example.com"}
	der, err := CreateCSR("ca", "cert.example.com", "NL", "NB", "Veldhoven", "Org", "OU", "x@y.com", dns, []net.IP{net.ParseIP("10.0.0.1")}, priv)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	assert.Equal(t, "cert.example.com", csr.Subject.CommonName)
	assert.Contains(t, csr.DNSNames, "cert.example.com")
	assert.Contains(t, csr.DNSNames, "a.example.com")
	// Caller slice must not be mutated.
	assert.Equal(t, []string{"a.example.com"}, dns)
}

// ---- LoadCSRFromPem ----

func TestLoadCSRFromPem_Empty(t *testing.T) {
	_, err := LoadCSRFromPem(nil)
	assert.Error(t, err)
}

func TestLoadCSRFromPem_Invalid(t *testing.T) {
	_, err := LoadCSRFromPem([]byte("garbage"))
	assert.Error(t, err)
}

func TestLoadCSRFromPem_RoundTrip(t *testing.T) {
	priv := testKey(t, 2048)
	der, err := CreateCSR("ca", "cn", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, priv)
	require.NoError(t, err)
	pem, err := ConvertCSRFromDerToPem(der)
	require.NoError(t, err)
	loaded, err := LoadCSRFromPem(pem)
	require.NoError(t, err)
	assert.Equal(t, "cn", loaded.Subject.CommonName)
}

// ---- CreateRootCert ----

func TestCreateRootCert(t *testing.T) {
	priv := testKey(t, 2048)
	der, err := CreateRootCert("ca", "root.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, priv, &priv.PublicKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.True(t, cert.IsCA)
	assert.Equal(t, "root.example.com", cert.Subject.CommonName)
	assert.Equal(t, cert.Subject, cert.Issuer) // self-signed
}

func TestCreateRootCert_DefaultValidity(t *testing.T) {
	priv := testKey(t, 2048)
	der, err := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 0, nil, nil, priv, &priv.PublicKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().AddDate(0, 0, DefaultValidCACert), cert.NotAfter, time.Minute)
}

func TestCreateCACert_InvalidValidity(t *testing.T) {
	priv := testKey(t, 2048)
	_, err := CreateCACert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", -1, nil, nil, priv, nil, nil, &priv.PublicKey)
	assert.Error(t, err)
	_, err = CreateCACert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 99999, nil, nil, priv, nil, nil, &priv.PublicKey)
	assert.Error(t, err)
}

// ---- CreateCACert intermediate ----

func TestCreateCACert_Intermediate(t *testing.T) {
	rootPriv := testKey(t, 2048)
	rootDer, err := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, rootPriv, &rootPriv.PublicKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)

	intPriv := testKey(t, 2048)
	intDer, err := CreateCACert("ca", "inter", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, intPriv, rootPriv, rootCert, &intPriv.PublicKey)
	require.NoError(t, err)
	intCert, err := x509.ParseCertificate(intDer)
	require.NoError(t, err)
	assert.True(t, intCert.IsCA)
	assert.Equal(t, rootCert.Subject, intCert.Issuer)
}

// ---- CASignCSR ----

func TestCASignCSR_DefaultType(t *testing.T) {
	rootPriv := testKey(t, 2048)
	rootDer, err := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, rootPriv, &rootPriv.PublicKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)

	certPriv := testKey(t, 2048)
	csrDer, err := CreateCSR("ca", "client.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, certPriv)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDer)
	require.NoError(t, err)

	der, err := CASignCSR("ca", csr, rootCert, rootPriv, 30, "")
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	// Default type = server-client
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestCASignCSR_ServerType(t *testing.T) {
	rootPriv := testKey(t, 2048)
	rootDer, _ := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, rootPriv, &rootPriv.PublicKey)
	rootCert, _ := x509.ParseCertificate(rootDer)

	certPriv := testKey(t, 2048)
	csrDer, _ := CreateCSR("ca", "server.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, certPriv)
	csr, _ := x509.ParseCertificateRequest(csrDer)

	der, err := CASignCSR("ca", csr, rootCert, rootPriv, 30, "server")
	require.NoError(t, err)
	c, _ := x509.ParseCertificate(der)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.NotContains(t, c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestCASignCSR_EmailType(t *testing.T) {
	rootPriv := testKey(t, 2048)
	rootDer, _ := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, rootPriv, &rootPriv.PublicKey)
	rootCert, _ := x509.ParseCertificate(rootDer)

	certPriv := testKey(t, 2048)
	csrDer, _ := CreateCSR("ca", "user@example.com", "NL", "NB", "L", "O", "OU", "user@example.com", nil, nil, certPriv)
	csr, _ := x509.ParseCertificateRequest(csrDer)

	der, err := CASignCSR("ca", csr, rootCert, rootPriv, 30, "email")
	require.NoError(t, err)
	c, _ := x509.ParseCertificate(der)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
}

func TestCASignCSR_UnknownType(t *testing.T) {
	rootPriv := testKey(t, 2048)
	rootDer, _ := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, rootPriv, &rootPriv.PublicKey)
	rootCert, _ := x509.ParseCertificate(rootDer)

	certPriv := testKey(t, 2048)
	csrDer, _ := CreateCSR("ca", "x", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, certPriv)
	csr, _ := x509.ParseCertificateRequest(csrDer)

	_, err := CASignCSR("ca", csr, rootCert, rootPriv, 30, "nfc-token")
	assert.ErrorIs(t, err, ErrUnknownCertType)
}

func TestCASignCSR_InvalidValidity(t *testing.T) {
	rootPriv := testKey(t, 2048)
	rootDer, _ := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, rootPriv, &rootPriv.PublicKey)
	rootCert, _ := x509.ParseCertificate(rootDer)

	certPriv := testKey(t, 2048)
	csrDer, _ := CreateCSR("ca", "x", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, certPriv)
	csr, _ := x509.ParseCertificateRequest(csrDer)

	_, err := CASignCSR("ca", csr, rootCert, rootPriv, 0, "") // 0 is OK (default)
	assert.NoError(t, err)
	_, err = CASignCSR("ca", csr, rootCert, rootPriv, 99999, "")
	assert.Error(t, err)
}

// ---- RevokeCertificate + CRL ----

func TestRevokeCertificate(t *testing.T) {
	rootPriv := testKey(t, 2048)
	rootDer, _ := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, rootPriv, &rootPriv.PublicKey)
	rootCert, _ := x509.ParseCertificate(rootDer)

	// Empty CRL
	emptyCRL, err := RevokeCertificate("ca", nil, rootCert, rootPriv)
	require.NoError(t, err)
	parsed, err := x509.ParseRevocationList(emptyCRL)
	require.NoError(t, err)
	assert.Empty(t, parsed.RevokedCertificates)

	// CRL with one revoked cert
	revoked := []pkix.RevokedCertificate{
		{SerialNumber: big.NewInt(42), RevocationTime: time.Now()},
	}
	crl, err := RevokeCertificate("ca", revoked, rootCert, rootPriv)
	require.NoError(t, err)
	parsed, err = x509.ParseRevocationList(crl)
	require.NoError(t, err)
	assert.Len(t, parsed.RevokedCertificates, 1)
}
