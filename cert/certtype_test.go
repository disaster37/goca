package cert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCertType(t *testing.T) {
	cases := []struct {
		in   string
		want CertType
	}{
		{"", DefaultCertType},
		{"server", CertTypeServer},
		{"SERVER", CertTypeServer},
		{"Server", CertTypeServer},
		{"client", CertTypeClient},
		{"server-client", CertTypeServerClient},
		{"Server_Client", CertTypeServerClient},
		{"server client", CertTypeServerClient},
		{"  email  ", CertTypeEmail},
		{"code-signing", CertTypeCodeSigning},
		{"code_signing", CertTypeCodeSigning},
		{"ocsp-responder", CertTypeOCSPResponder},
		{"time-stamping", CertTypeTimeStamping},
	}
	for _, c := range cases {
		got, err := ParseCertType(c.in)
		require.NoError(t, err, "input %q", c.in)
		assert.Equal(t, c.want, got, "input %q", c.in)
	}
}

func TestParseCertType_Unknown(t *testing.T) {
	_, err := ParseCertType("nfc-token")
	assert.ErrorIs(t, err, ErrUnknownCertType)
}

func TestCertTypeUsage_AllTypes(t *testing.T) {
	types := []CertType{
		CertTypeServer, CertTypeClient, CertTypeServerClient,
		CertTypeEmail, CertTypeCodeSigning, CertTypeOCSPResponder,
		CertTypeTimeStamping,
	}
	for _, ty := range types {
		ku, eku, err := certTypeUsage(ty)
		require.NoError(t, err)
		assert.NotZero(t, ku, "type %s", ty)
		assert.NotEmpty(t, eku, "type %s", ty)
	}
}

func TestCertTypeUsage_Unknown(t *testing.T) {
	_, _, err := certTypeUsage(CertType("bogus"))
	assert.ErrorIs(t, err, ErrUnknownCertType)
}
