package cert

import (
	"crypto/x509"

	"github.com/pkg/errors"
)

// CertType describes the intended use of an end-entity certificate using a
// business vocabulary that hides crypto/x509 KeyUsage/ExtKeyUsage details.
type CertType string

const (
	// CertTypeServer is a TLS server certificate (HTTPS, LDAPS, IMAPS, ...).
	CertTypeServer CertType = "server"

	// CertTypeClient is a TLS client certificate (mutual TLS authentication).
	CertTypeClient CertType = "client"

	// CertTypeServerClient is both server and client. This is the historical
	// default behavior of goca and is kept for backward compatibility.
	CertTypeServerClient CertType = "server-client"

	// CertTypeEmail is an S/MIME certificate for signing and encrypting email.
	CertTypeEmail CertType = "email"

	// CertTypeCodeSigning is a code-signing certificate (binaries, packages).
	CertTypeCodeSigning CertType = "code-signing"

	// CertTypeOCSPResponder is a certificate allowed to sign OCSP responses.
	CertTypeOCSPResponder CertType = "ocsp-responder"

	// CertTypeTimeStamping is a Time Stamping Authority certificate (RFC 3161).
	CertTypeTimeStamping CertType = "time-stamping"
)

// DefaultCertType is used when the user does not specify a Type.
const DefaultCertType = CertTypeServerClient

// ErrUnknownCertType is returned when a Type string does not match any known
// CertType.
var ErrUnknownCertType = errors.New("unknown certificate type; accepted values: server, client, server-client, email, code-signing, ocsp-responder, time-stamping")

type certTypeUsageSpec struct {
	keyUsage    x509.KeyUsage
	extKeyUsage []x509.ExtKeyUsage
}

var certTypeUsageTable = map[CertType]certTypeUsageSpec{
	CertTypeServer: {
		keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	},
	CertTypeClient: {
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	},
	CertTypeServerClient: {
		keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	},
	CertTypeEmail: {
		keyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	},
	CertTypeCodeSigning: {
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	},
	CertTypeOCSPResponder: {
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	},
	CertTypeTimeStamping: {
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	},
}

// ParseCertType converts a user string into a CertType.
// Matching is case-insensitive and treats underscores, spaces, and hyphens
// as equivalent. An empty string yields DefaultCertType.
func ParseCertType(s string) (CertType, error) {
	normalized := normalizeCertTypeString(s)
	if normalized == "" {
		return DefaultCertType, nil
	}
	t := CertType(normalized)
	if _, ok := certTypeUsageTable[t]; !ok {
		return "", ErrUnknownCertType
	}
	return t, nil
}

func normalizeCertTypeString(s string) string {
	if len(s) == 0 {
		return ""
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case c == '_' || c == ' ':
			out = append(out, '-')
		default:
			out = append(out, c)
		}
	}
	// trim leading/trailing hyphens
	for len(out) > 0 && out[0] == '-' {
		out = out[1:]
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	return string(out)
}

// certTypeUsage returns the x509 KeyUsage and ExtKeyUsage for a CertType.
// Internal: users of the library never call this.
func certTypeUsage(t CertType) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	spec, ok := certTypeUsageTable[t]
	if !ok {
		return 0, nil, ErrUnknownCertType
	}
	ext := make([]x509.ExtKeyUsage, len(spec.extKeyUsage))
	copy(ext, spec.extKeyUsage)
	return spec.keyUsage, ext, nil
}
