package goca

import "github.com/disaster37/goca/cert"

// CertType is an alias for cert.CertType, re-exported so users of the goca
// package do not need to import the cert subpackage directly.
type CertType = cert.CertType

// Re-exported CertType constants.
const (
	CertTypeServer        = cert.CertTypeServer
	CertTypeClient        = cert.CertTypeClient
	CertTypeServerClient  = cert.CertTypeServerClient
	CertTypeEmail         = cert.CertTypeEmail
	CertTypeCodeSigning   = cert.CertTypeCodeSigning
	CertTypeOCSPResponder = cert.CertTypeOCSPResponder
	CertTypeTimeStamping  = cert.CertTypeTimeStamping
)

// DefaultCertType is the default certificate type when none is specified.
const DefaultCertType = cert.DefaultCertType

// ParseCertType re-exports cert.ParseCertType.
func ParseCertType(s string) (cert.CertType, error) {
	return cert.ParseCertType(s)
}
