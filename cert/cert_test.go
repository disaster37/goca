package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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

func TestCreateCSR_DNSDedupe(t *testing.T) {
	priv := testKey(t, 2048)
	dns := []string{"cert.example.com", "a.example.com"}
	der, err := CreateCSR("ca", "cert.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", dns, nil, priv)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	// commonName already present: must not be appended twice.
	assert.Equal(t, []string{"cert.example.com", "a.example.com"}, csr.DNSNames)
	assert.Equal(t, []string{"cert.example.com", "a.example.com"}, dns)
}

func TestCreateCSR_EmailIncluded(t *testing.T) {
	priv := testKey(t, 2048)
	der, err := CreateCSR("ca", "cn.example.com", "NL", "NB", "L", "O", "OU", "user@example.com", nil, nil, priv)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	assert.Equal(t, []string{"user@example.com"}, csr.EmailAddresses)
	// Email OID 1.2.840.113549.1.9.1 present in the raw subject.
	emailOIDDER := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01}
	assert.Contains(t, string(csr.RawSubject), string(emailOIDDER))
}

func TestCreateCSR_EmptyEmailOmitted(t *testing.T) {
	priv := testKey(t, 2048)
	der, err := CreateCSR("ca", "cn.example.com", "NL", "NB", "L", "O", "OU", "", nil, nil, priv)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	assert.Empty(t, csr.EmailAddresses)
	emailOIDDER := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01}
	assert.NotContains(t, string(csr.RawSubject), string(emailOIDDER))
}

func TestCreateCSR_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := CreateCSR("ca", "cn.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	assert.NoError(t, csr.CheckSignature())
	// SignatureAlgorithm must be auto-selected for the key type.
	assert.Equal(t, x509.ECDSAWithSHA256, csr.SignatureAlgorithm)
}

func TestCreateCSR_Ed25519(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := CreateCSR("ca", "cn.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	assert.NoError(t, csr.CheckSignature())
	assert.Equal(t, x509.PureEd25519, csr.SignatureAlgorithm)
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

// ---- CreateCACert hygiene ----

func TestCreateCACert_NoExtKeyUsage(t *testing.T) {
	priv := testKey(t, 2048)
	der, err := CreateCACert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, priv, nil, nil, &priv.PublicKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.True(t, cert.IsCA)
	// CAs must not carry end-entity EKUs.
	assert.Empty(t, cert.ExtKeyUsage)
}

func TestCreateCACert_DNSDedupe(t *testing.T) {
	priv := testKey(t, 2048)
	dns := []string{"root.example.com", "alt.example.com"}
	der, err := CreateCACert("ca", "root.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", 365, dns, nil, priv, nil, nil, &priv.PublicKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, []string{"root.example.com", "alt.example.com"}, cert.DNSNames)
	assert.Equal(t, []string{"root.example.com", "alt.example.com"}, dns)
}

func TestCreateCACert_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := CreateCACert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, priv, nil, nil, &priv.PublicKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.True(t, cert.IsCA)
	assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)
	assert.NoError(t, cert.CheckSignatureFrom(cert))
}

func TestCreateCACert_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := CreateCACert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, priv, nil, nil, priv.Public())
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.True(t, cert.IsCA)
	assert.Equal(t, x509.Ed25519, cert.PublicKeyAlgorithm)
	assert.NoError(t, cert.CheckSignatureFrom(cert))
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

// ---- CASignCSRWithOptions ----

func signWithOptions(t *testing.T, opts SignOptions) (*x509.Certificate, error) {
	t.Helper()
	rootPriv := testKey(t, 2048)
	rootDer, err := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", MaxValidCACert, nil, nil, rootPriv, &rootPriv.PublicKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)

	certPriv := testKey(t, 2048)
	csrDer, err := CreateCSR("ca", "client.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, certPriv)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDer)
	require.NoError(t, err)

	der, err := CASignCSRWithOptions("ca", csr, rootCert, rootPriv, opts)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return c, nil
}

func TestCASignCSRWithOptions_SubDayDuration(t *testing.T) {
	c, err := signWithOptions(t, SignOptions{ValidDuration: 5 * time.Minute, CertType: "server"})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(5*time.Minute), c.NotAfter, time.Minute)
	assert.WithinDuration(t, time.Now(), c.NotBefore, time.Minute)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestCASignCSRWithOptions_DefaultDays(t *testing.T) {
	c, err := signWithOptions(t, SignOptions{})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().AddDate(0, 0, DefaultValidCert), c.NotAfter, time.Minute)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestCASignCSRWithOptions_ValidDays(t *testing.T) {
	c, err := signWithOptions(t, SignOptions{ValidDays: 30, CertType: "client"})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().AddDate(0, 0, 30), c.NotAfter, time.Minute)
	assert.Contains(t, c.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestCASignCSRWithOptions_DurationTooSmall(t *testing.T) {
	_, err := signWithOptions(t, SignOptions{ValidDuration: 30 * time.Second})
	assert.Error(t, err)
}

func TestCASignCSRWithOptions_DurationTooLarge(t *testing.T) {
	tooLarge := time.Duration(MaxValidCert)*24*time.Hour + time.Hour
	_, err := signWithOptions(t, SignOptions{ValidDuration: tooLarge})
	assert.Error(t, err)
}

func TestCASignCSRWithOptions_InvalidDays(t *testing.T) {
	_, err := signWithOptions(t, SignOptions{ValidDays: 0 - 1})
	assert.Error(t, err)
	_, err = signWithOptions(t, SignOptions{ValidDays: MaxValidCert + 1})
	assert.Error(t, err)
}

func TestCASignCSRWithOptions_ExplicitNotBefore(t *testing.T) {
	notBefore := time.Now().Add(-5 * time.Minute)
	c, err := signWithOptions(t, SignOptions{ValidDays: 30, NotBefore: notBefore})
	require.NoError(t, err)
	assert.WithinDuration(t, notBefore, c.NotBefore, time.Second)
}

func TestCASignCSRWithOptions_Backdate(t *testing.T) {
	c, err := signWithOptions(t, SignOptions{ValidDays: 30, Backdate: 5 * time.Minute})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(-5*time.Minute), c.NotBefore, time.Minute)
}

func TestCASignCSRWithOptions_NotBeforeClampedToCA(t *testing.T) {
	// Backdate further than the CA's own NotBefore (-10min): clamped.
	c, err := signWithOptions(t, SignOptions{ValidDays: 30, Backdate: time.Hour})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(-10*time.Minute), c.NotBefore, time.Minute)
}

func TestCASignCSRWithOptions_NotAfterClampedToCA(t *testing.T) {
	// CA with 1-day validity: the 30-day leaf NotAfter must be clamped to it.
	rootPriv := testKey(t, 2048)
	rootDer, err := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 1, nil, nil, rootPriv, &rootPriv.PublicKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)

	certPriv := testKey(t, 2048)
	csrDer, err := CreateCSR("ca", "client.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, certPriv)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDer)
	require.NoError(t, err)

	der, err := CASignCSRWithOptions("ca", csr, rootCert, rootPriv, SignOptions{ValidDays: 30})
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.WithinDuration(t, rootCert.NotAfter, c.NotAfter, time.Second)
}

func TestCASignCSRWithOptions_WindowInvertedAfterClamp(t *testing.T) {
	// Explicit NotBefore beyond any possible NotAfter: the clamped window is
	// inverted and must be rejected.
	notBefore := time.Now().AddDate(0, 0, MaxValidCert+1)
	_, err := signWithOptions(t, SignOptions{ValidDays: 30, NotBefore: notBefore})
	assert.Error(t, err)
}

func TestCASignCSRWithOptions_InvalidCSRSignature(t *testing.T) {
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
	csr.Signature[0] ^= 0xff

	_, err = CASignCSRWithOptions("ca", csr, rootCert, rootPriv, SignOptions{})
	assert.ErrorIs(t, err, ErrCSRSignatureInvalid)
}

func TestCASignCSRWithOptions_ECDSACA(t *testing.T) {
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootDer, err := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, rootPriv, &rootPriv.PublicKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)

	certPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDer, err := CreateCSR("ca", "client.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, certPriv)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDer)
	require.NoError(t, err)

	der, err := CASignCSRWithOptions("ca", csr, rootCert, rootPriv, SignOptions{ValidDays: 30, CertType: "client"})
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, c.PublicKeyAlgorithm)
	assert.NoError(t, c.CheckSignatureFrom(rootCert))
}

func TestCASignCSRWithOptions_Ed25519CA(t *testing.T) {
	_, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rootDer, err := CreateRootCert("ca", "root", "NL", "NB", "L", "O", "OU", "e@x.com", 365, nil, nil, rootPriv, rootPriv.Public())
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDer)
	require.NoError(t, err)

	_, certPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	csrDer, err := CreateCSR("ca", "client.example.com", "NL", "NB", "L", "O", "OU", "e@x.com", nil, nil, certPriv)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDer)
	require.NoError(t, err)

	der, err := CASignCSRWithOptions("ca", csr, rootCert, rootPriv, SignOptions{ValidDays: 30, CertType: "client"})
	require.NoError(t, err)
	c, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, x509.Ed25519, c.PublicKeyAlgorithm)
	assert.NoError(t, c.CheckSignatureFrom(rootCert))
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
