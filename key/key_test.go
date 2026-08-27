package key

import (
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
