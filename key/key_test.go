package key

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateKeys_DefaultSize(t *testing.T) {
	kd, err := CreateKeys("ca", "cert", 0)
	require.NoError(t, err)
	assert.NotNil(t, kd.Key)
	assert.NotNil(t, kd.PublicKey)
	assert.Equal(t, DefaultKeyBitSize, kd.Key.N.BitLen())
}

func TestCreateKeys_TooSmall(t *testing.T) {
	_, err := CreateKeys("ca", "cert", 1024)
	assert.ErrorIs(t, err, ErrKeyBitSizeTooSmall)
}

func TestCreateKeys_NotMultipleOf8(t *testing.T) {
	_, err := CreateKeys("ca", "cert", 2049)
	assert.Error(t, err)
}

func TestCreateKeys_4096(t *testing.T) {
	kd, err := CreateKeys("ca", "cert", 4096)
	require.NoError(t, err)
	assert.Equal(t, 4096, kd.Key.N.BitLen())
}

func TestLoadPrivateKeyFromPem_PKCS8(t *testing.T) {
	kd, err := CreateKeys("ca", "cert", 2048)
	require.NoError(t, err)
	pem, err := ConvertPrivateKeyFromDerToPem(kd.Key)
	require.NoError(t, err)

	loaded, err := LoadPrivateKeyFromPem(pem)
	require.NoError(t, err)
	assert.True(t, kd.Key.Equal(loaded))
}

func TestLoadPrivateKeyFromPem_Empty(t *testing.T) {
	_, err := LoadPrivateKeyFromPem(nil)
	assert.Error(t, err)
}

func TestLoadPrivateKeyFromPem_Invalid(t *testing.T) {
	_, err := LoadPrivateKeyFromPem([]byte("not a pem"))
	assert.Error(t, err)
}

func TestLoadPublicKeyFromPem_RoundTrip(t *testing.T) {
	kd, err := CreateKeys("ca", "cert", 2048)
	require.NoError(t, err)
	pem, err := ConvertPublicKeyFromDerToPem(kd.PublicKey)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(pem), "-----BEGIN PUBLIC KEY-----"))

	loaded, err := LoadPublicKeyFromPem(pem)
	require.NoError(t, err)
	assert.Equal(t, kd.PublicKey.N, loaded.N)
	assert.Equal(t, kd.PublicKey.E, loaded.E)
}

func TestLoadPublicKeyFromPem_Empty(t *testing.T) {
	_, err := LoadPublicKeyFromPem(nil)
	assert.Error(t, err)
}

func TestConvertRsaPrivateKeyFromDerToPem(t *testing.T) {
	kd, err := CreateKeys("ca", "cert", 2048)
	require.NoError(t, err)
	pemBytes, err := ConvertRsaPrivateKeyFromDerToPem(kd.Key)
	require.NoError(t, err)
	assert.Contains(t, string(pemBytes), "RSA PRIVATE KEY")

	// Round-trip via LoadPrivateKeyFromPem (which accepts PKCS#1).
	loaded, err := LoadPrivateKeyFromPem(pemBytes)
	require.NoError(t, err)
	assert.True(t, kd.Key.Equal(loaded))
}

// ---- CreateKeyPair ----

func TestCreateKeyPair_RSA_Default(t *testing.T) {
	kp, err := CreateKeyPair(KeyAlgorithmRSA, 0)
	require.NoError(t, err)
	assert.Equal(t, KeyAlgorithmRSA, kp.Algorithm)
	key, ok := kp.Key.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, DefaultKeyBitSize, key.N.BitLen())
}

func TestCreateKeyPair_EmptyAlgorithmDefaultsToRSA(t *testing.T) {
	kp, err := CreateKeyPair("", 2048)
	require.NoError(t, err)
	assert.Equal(t, KeyAlgorithmRSA, kp.Algorithm)
	_, ok := kp.Key.(*rsa.PrivateKey)
	assert.True(t, ok)
}

func TestCreateKeyPair_RSA_Validation(t *testing.T) {
	_, err := CreateKeyPair(KeyAlgorithmRSA, 1024)
	assert.ErrorIs(t, err, ErrKeyBitSizeTooSmall)
	_, err = CreateKeyPair(KeyAlgorithmRSA, 2049)
	assert.Error(t, err)
}

func TestCreateKeyPair_ECDSAP256(t *testing.T) {
	kp, err := CreateKeyPair(KeyAlgorithmECDSAP256, 0)
	require.NoError(t, err)
	assert.Equal(t, KeyAlgorithmECDSAP256, kp.Algorithm)
	key, ok := kp.Key.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P256(), key.Curve)
}

func TestCreateKeyPair_Ed25519(t *testing.T) {
	kp, err := CreateKeyPair(KeyAlgorithmEd25519, 0)
	require.NoError(t, err)
	assert.Equal(t, KeyAlgorithmEd25519, kp.Algorithm)
	_, ok := kp.Key.(ed25519.PrivateKey)
	assert.True(t, ok)
}

func TestCreateKeyPair_UnknownAlgorithm(t *testing.T) {
	_, err := CreateKeyPair("dsa", 2048)
	assert.ErrorIs(t, err, ErrUnknownKeyAlgorithm)
}

// ---- LoadSignerFromPem ----

func TestLoadSignerFromPem_RSA_PKCS1(t *testing.T) {
	kd, err := CreateKeys("ca", "cert", 2048)
	require.NoError(t, err)
	pemBytes, err := ConvertRsaPrivateKeyFromDerToPem(kd.Key)
	require.NoError(t, err)

	signer, err := LoadSignerFromPem(pemBytes)
	require.NoError(t, err)
	key, ok := signer.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.True(t, kd.Key.Equal(key))
}

func TestLoadSignerFromPem_RSA_PKCS8(t *testing.T) {
	kd, err := CreateKeys("ca", "cert", 2048)
	require.NoError(t, err)
	pemBytes, err := ConvertPrivateKeyFromDerToPem(kd.Key)
	require.NoError(t, err)

	signer, err := LoadSignerFromPem(pemBytes)
	require.NoError(t, err)
	key, ok := signer.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.True(t, kd.Key.Equal(key))
}

func TestLoadSignerFromPem_EC_SEC1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	derBytes, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})

	signer, err := LoadSignerFromPem(pemBytes)
	require.NoError(t, err)
	loaded, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.True(t, key.Equal(loaded))
}

func TestLoadSignerFromPem_Ed25519_PKCS8(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pemBytes, err := ConvertSignerToPem(key)
	require.NoError(t, err)

	signer, err := LoadSignerFromPem(pemBytes)
	require.NoError(t, err)
	loaded, ok := signer.(ed25519.PrivateKey)
	require.True(t, ok)
	assert.True(t, key.Equal(loaded))
}

func TestLoadSignerFromPem_Empty(t *testing.T) {
	_, err := LoadSignerFromPem(nil)
	assert.Error(t, err)
}

func TestLoadSignerFromPem_Invalid(t *testing.T) {
	_, err := LoadSignerFromPem([]byte("not a pem"))
	assert.Error(t, err)
}

func TestLoadSignerFromPem_UnsupportedBlockType(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01}})
	_, err := LoadSignerFromPem(pemBytes)
	assert.Error(t, err)
}

// ---- LoadAnyPublicKeyFromPem ----

func TestLoadAnyPublicKeyFromPem_RSA_PKIX(t *testing.T) {
	kd, err := CreateKeys("ca", "cert", 2048)
	require.NoError(t, err)
	pemBytes, err := ConvertPublicKeyFromDerToPem(kd.PublicKey)
	require.NoError(t, err)

	pub, err := LoadAnyPublicKeyFromPem(pemBytes)
	require.NoError(t, err)
	loaded, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, kd.PublicKey.N, loaded.N)
	assert.Equal(t, kd.PublicKey.E, loaded.E)
}

func TestLoadAnyPublicKeyFromPem_RSA_PKCS1(t *testing.T) {
	kd, err := CreateKeys("ca", "cert", 2048)
	require.NoError(t, err)
	derBytes := x509.MarshalPKCS1PublicKey(kd.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: derBytes})

	pub, err := LoadAnyPublicKeyFromPem(pemBytes)
	require.NoError(t, err)
	loaded, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, kd.PublicKey.N, loaded.N)
	assert.Equal(t, kd.PublicKey.E, loaded.E)
}

func TestLoadAnyPublicKeyFromPem_ECDSA(t *testing.T) {
	kp, err := CreateKeyPair(KeyAlgorithmECDSAP256, 0)
	require.NoError(t, err)
	pemBytes, err := ConvertAnyPublicKeyToPem(kp.PublicKey)
	require.NoError(t, err)

	pub, err := LoadAnyPublicKeyFromPem(pemBytes)
	require.NoError(t, err)
	loaded, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, kp.PublicKey.(*ecdsa.PublicKey).Equal(loaded))
}

func TestLoadAnyPublicKeyFromPem_Ed25519(t *testing.T) {
	kp, err := CreateKeyPair(KeyAlgorithmEd25519, 0)
	require.NoError(t, err)
	pemBytes, err := ConvertAnyPublicKeyToPem(kp.PublicKey)
	require.NoError(t, err)

	pub, err := LoadAnyPublicKeyFromPem(pemBytes)
	require.NoError(t, err)
	loaded, ok := pub.(ed25519.PublicKey)
	require.True(t, ok)
	assert.True(t, kp.PublicKey.(ed25519.PublicKey).Equal(loaded))
}

func TestLoadAnyPublicKeyFromPem_Empty(t *testing.T) {
	_, err := LoadAnyPublicKeyFromPem(nil)
	assert.Error(t, err)
}

func TestLoadAnyPublicKeyFromPem_Invalid(t *testing.T) {
	_, err := LoadAnyPublicKeyFromPem([]byte("not a pem"))
	assert.Error(t, err)
}

// ---- ConvertSignerToPem / ConvertAnyPublicKeyToPem ----

func TestConvertSignerToPem_RoundTrip(t *testing.T) {
	algorithms := []KeyAlgorithm{KeyAlgorithmRSA, KeyAlgorithmECDSAP256, KeyAlgorithmEd25519}
	for _, alg := range algorithms {
		kp, err := CreateKeyPair(alg, 2048)
		require.NoError(t, err, "algorithm %s", alg)

		pemBytes, err := ConvertSignerToPem(kp.Key)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(pemBytes), "-----BEGIN PRIVATE KEY-----"), "algorithm %s", alg)

		loaded, err := LoadSignerFromPem(pemBytes)
		require.NoError(t, err)
		pubPem, err := ConvertAnyPublicKeyToPem(loaded.Public())
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(pubPem), "-----BEGIN PUBLIC KEY-----"))
	}
}
