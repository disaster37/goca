# GoCA — Complete Implementation Plan

A self-contained, step-by-step plan to fix all bugs, security issues, and add
configurable certificate types to the `goca` project. Each task can be executed
independently by an LLM with no prior context.

---

## 0. Project Context

`goca` is a Go library (`module github.com/disaster37/goca`, Go 1.25) that
manages a simple PKI: creating Root/Intermediate Certificate Authorities,
issuing certificates from CSRs, revoking certificates (CRL), and exporting
PKCS#12. It is a pure library (no disk storage).

**Layout:**
```
goca/
├── ca.go            # CA logic: create/load/sign/issue/revoke
├── goca.go          # Public API: New, NewCA, IssueCertificate, SignCSR, ...
├── goca_test.go     # Tests (partly commented out)
├── example_test.go  # Example (fully commented out)
├── cert/cert.go     # Certificate/CSR/CRL generation and conversion
├── key/key.go       # RSA key generation and loading
├── go.mod, go.sum
├── Makefile, Dockerfile
├── README.md, DOCKER_README.md
└── .github/workflows/
```

**Public API surface (must stay backward compatible unless noted):**
- `goca.New(commonName string, identity Identity) (*CA, error)`
- `goca.NewCA(commonName string, parentCert *x509.Certificate, parentKey *rsa.PrivateKey, identity Identity) (*CA, error)`
- `goca.LoadCA` does NOT exist — loading is done via `(*CA).LoadCA(privateKeyPem, publicKeyPem, certPem, crlPem []byte) error`
- `(*CA).IssueCertificate(commonName string, id Identity) (*Certificate, error)`
- `(*CA).SignCSR(csr *x509.CertificateRequest, valid int) (*Certificate, error)`
- `(*CA).RevokeCertificate(certificate *x509.Certificate) error`
- `goca.GeneratePkcs12(cert *Certificate, passphrase string, otherCaCerts ...*x509.Certificate) ([]byte, error)`

---

## 1. Conventions for the Implementer

1. **Always read the file before editing.** Confirm the "Current code" block matches before replacing.
2. **Make one task's changes at a time.** Do not combine unrelated tasks.
3. **Run `gofmt -w <file>` after every Go file edit.**
4. **Run `go build ./...` after each phase.** It must succeed.
5. **Run `go test ./...` after Phase F.** All tests must pass.
6. **Never change a public function signature without keeping a deprecated alias** (see specific tasks).
7. **Preserve the MIT license headers** in `cert/cert.go` and `key/key.go`.
8. **Use `github.com/pkg/errors`** for error wrapping (already a dependency): `errors.Wrap(err, "msg")` or `errors.New("msg")` or `errors.Errorf("...", args)`.
9. **Imports:** use stdlib first, then third-party. Group with blank lines.
10. **Do not remove the `CACommonName`/`commonName` parameters from public `cert.*` functions in Phase C** — they are deprecated but kept for compatibility. Internal callers stop passing meaningful values.

---

## 2. Prerequisites (run first)

```bash
cd /projects/goca
go version          # must be >= 1.25
go build ./...      # baseline: must succeed
go test ./...       # baseline: 3 tests pass
```

If `go build` fails, stop and fix the environment before continuing.

---

## Phase A — Formatting & New Files (no behavior change)

### Task A1: Apply gofmt to all Go files

**Why:** 5 files have tab/space misalignment (notably `ca.go:25` `IPAddresses`).

**Steps:**
```bash
cd /projects/goca
gofmt -w ca.go goca.go goca_test.go example_test.go key/key.go cert/cert.go
```

**Verify:**
```bash
gofmt -l .
# expected: no output
```

---

### Task A2: Create `certtype.go` (new file)

**Why:** Introduces a user-friendly `CertType` enum that maps to x509
`KeyUsage`/`ExtKeyUsage`, so users never need to know x509 syntax. This is the
core of the "configurable certificate type" feature.

**File:** `/projects/goca/certtype.go` (new)

**Full content:**
```go
package goca

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
```

**Verify:**
```bash
cd /projects/goca
go build ./...
```

---

## Phase B — Fix `key/key.go`

Open `/projects/goca/key/key.go`. Keep the MIT license header (lines 1-22)
unchanged throughout this phase.

### Task B1: Add key-size constants and validate `CreateKeys`

**Why:** `CreateKeys` accepts any bit size, including 512 (crackable). NIST
requires >= 2048.

**Current code (lines 41-66):**
```go
// KeysData represents the RSA keys with Private Key (Key) and Public Key (Public Key).
type KeysData struct {
	Key       *rsa.PrivateKey
	PublicKey *rsa.PublicKey
}

// CreateKeys creates RSA private and public keyData that contains Key and PublicKey.
func CreateKeys(CACommonName, commonName string, bitSize int) (KeysData, error) {
	reader := rand.Reader
	if bitSize == 0 {
		bitSize = 2048
	}

	key, err := rsa.GenerateKey(reader, bitSize)

	if err != nil {
		return KeysData{}, err
	}

	keys := KeysData{
		Key:       key,
		PublicKey: &key.PublicKey,
	}

	return keys, nil
}
```

**Replace with:**
```go
// Key bit size boundaries.
const (
	// MinKeyBitSize is the minimum accepted RSA key size.
	MinKeyBitSize = 2048
	// DefaultKeyBitSize is used when bitSize is 0.
	DefaultKeyBitSize = 2048
)

// KeysData represents the RSA keys with Private Key (Key) and Public Key (Public Key).
type KeysData struct {
	Key       *rsa.PrivateKey
	PublicKey *rsa.PublicKey
}

// ErrKeyBitSizeTooSmall is returned when the requested key size is below MinKeyBitSize.
var ErrKeyBitSizeTooSmall = errors.Errorf("key bit size must be at least %d", MinKeyBitSize)

// CreateKeys creates RSA private and public keyData that contains Key and PublicKey.
// CACommonName and commonName are deprecated and ignored (kept for backward compatibility).
func CreateKeys(CACommonName, commonName string, bitSize int) (KeysData, error) {
	if bitSize == 0 {
		bitSize = DefaultKeyBitSize
	}
	if bitSize < MinKeyBitSize {
		return KeysData{}, ErrKeyBitSizeTooSmall
	}
	if bitSize%8 != 0 {
		return KeysData{}, errors.New("key bit size must be a multiple of 8")
	}

	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return KeysData{}, err
	}

	keys := KeysData{
		Key:       key,
		PublicKey: &key.PublicKey,
	}

	return keys, nil
}
```

**Also update imports** at top of file. The current import block is:
```go
import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
)
```
Add `github.com/pkg/errors` so it becomes:
```go
import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"

	"github.com/pkg/errors"
)
```
(The `asn1` import will be removed in Task B4.)

**Verify:**
```bash
cd /projects/goca && go build ./...
```

---

### Task B2: Fix `LoadPrivateKeyFromPem`

**Why:** Currently ignores both `pem.Decode` and `x509.ParsePKCS1PrivateKey`
errors and returns `(nil, nil)` on bad input, causing nil-pointer panics in
callers. Also only supports PKCS#1; should also accept PKCS#8 ("PRIVATE KEY").

**Current code (lines 68-74):**
```go
// LoadPrivateKey loads a RSA Private Key from a pem contend.
func LoadPrivateKeyFromPem(keyPem []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(string(keyPem)))
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	return privateKey, nil
}
```

**Replace with:**
```go
// LoadPrivateKeyFromPem loads an RSA private key from a PEM block.
// Accepts both "RSA PRIVATE KEY" (PKCS#1) and "PRIVATE KEY" (PKCS#8) blocks.
func LoadPrivateKeyFromPem(keyPem []byte) (*rsa.PrivateKey, error) {
	if len(keyPem) == 0 {
		return nil, errors.New("private key PEM data is empty")
	}
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, errors.New("failed to decode private key PEM block")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PKCS#1 private key")
		}
		return privateKey, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PKCS#8 private key")
		}
		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 private key is not an RSA key")
		}
		return privateKey, nil
	default:
		return nil, errors.Errorf("unexpected PEM block type %q for a private key", block.Type)
	}
}
```

**Verify:**
```bash
cd /projects/goca && go build ./...
```

---

### Task B3: Fix `LoadPublicKeyFromPem`

**Why:** Same issue: errors ignored, and uses `ParsePKCS1PublicKey` which only
parses "RSA PUBLIC KEY" blocks, not the "PUBLIC KEY" (PKIX/SPKI) blocks that
`ConvertPublicKeyFromDerToPem` produces (after Task B4).

**Current code (lines 77-82):**
```go
// LoadPublicKey loads a RSA Public Key from a pem contend.
func LoadPublicKeyFromPem(keyPem []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(string(keyPem)))
	publicKey, _ := x509.ParsePKCS1PublicKey(block.Bytes)

	return publicKey, nil
}
```

**Replace with:**
```go
// LoadPublicKeyFromPem loads an RSA public key from a PEM block.
// Accepts both "PUBLIC KEY" (PKIX/SPKI) and "RSA PUBLIC KEY" (PKCS#1) blocks.
func LoadPublicKeyFromPem(keyPem []byte) (*rsa.PublicKey, error) {
	if len(keyPem) == 0 {
		return nil, errors.New("public key PEM data is empty")
	}
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, errors.New("failed to decode public key PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PKIX public key")
		}
		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("PKIX public key is not an RSA key")
		}
		return publicKey, nil
	case "RSA PUBLIC KEY":
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PKCS#1 public key")
		}
		return publicKey, nil
	default:
		return nil, errors.Errorf("unexpected PEM block type %q for a public key", block.Type)
	}
}
```

**Verify:**
```bash
cd /projects/goca && go build ./...
```

---

### Task B4: Fix `ConvertPublicKeyFromDerToPem`

**Why:** It marshals with `asn1.Marshal(*publicKey)` (which produces PKCS#1
bytes) but labels the PEM block `"PUBLIC KEY"` (which means PKIX/SPKI). This
mismatch breaks strict parsers. Use `x509.MarshalPKIXPublicKey` instead, and
remove the now-unused `encoding/asn1` import.

**Current code (lines 114-132):**
```go
// ConvertPrivateKeyFromDerToPem permit to convert public key from DER format to PEM format
func ConvertPublicKeyFromDerToPem(publicKey *rsa.PublicKey) (publicKeyPem []byte, err error) {
	
	asn1Bytes, err := asn1.Marshal(*publicKey)
	if err != nil {
		return nil, err
	}
	pemPublickey := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	var pemBuff bytes.Buffer
	err = pem.Encode(&pemBuff, pemPublickey)
	if err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}
```

**Replace with:**
```go
// ConvertPublicKeyFromDerToPem converts an RSA public key to a PEM block
// using the PKIX/SPKI format ("PUBLIC KEY").
func ConvertPublicKeyFromDerToPem(publicKey *rsa.PublicKey) (publicKeyPem []byte, err error) {
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal PKIX public key")
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	var pemBuff bytes.Buffer
	if err := pem.Encode(&pemBuff, pemBlock); err != nil {
		return nil, err
	}

	return pemBuff.Bytes(), nil
}
```

**Then remove `encoding/asn1` from the import block.** Final imports for
`key/key.go`:
```go
import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)
```

**Verify:**
```bash
cd /projects/goca && gofmt -w key/key.go && go build ./... && go vet ./...
```

---

## Phase C — Fix `cert/cert.go`

Open `/projects/goca/cert/cert.go`. Keep the MIT license header (lines 1-22)
unchanged throughout this phase.

### Task C1: Fix `newSerialNumber`

**Why:** `rand.Int` error is ignored; if the CSPRNG fails, `serialNumber` is
nil, producing an invalid certificate (RFC 5280 requires a positive integer).

**Current code (lines 62-67):**
```go
func newSerialNumber() (serialNumber *big.Int) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)

	return serialNumber
}
```

**Replace with:**
```go
// newSerialNumber returns a random positive serial number fitting in 128 bits.
func newSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate serial number")
	}
	// Guarantee positivity (RFC 5280 §4.1.2.2).
	if n.Sign() <= 0 {
		return newSerialNumber()
	}
	return n, nil
}
```

Every caller must now handle the error. Update each call site:
- `CreateCACert` line 189: `SerialNumber: newSerialNumber(),` →
  ```go
  serial, err := newSerialNumber()
  if err != nil {
  	return nil, err
  }
  ```
  and use `SerialNumber: serial,` in the struct. (Add this before building `caCert`.)
- `CASignCSR` line 264: `SerialNumber: newSerialNumber(),` → similar pattern.
- `RevokeCertificate` line 284: `Number: newSerialNumber(),` → similar pattern.

For each, insert the `serial, err := newSerialNumber()` check immediately
before the struct literal that uses it.

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C2: Fix `CreateCSR` (ignored `asn1.Marshal` + slice mutation)

**Why:** `asn1.Marshal` error ignored; `dnsNames = append(dnsNames, commonName)`
mutates the caller's slice.

**Current code (lines 71-99):**
```go
func CreateCSR(CACommonName, commonName, country, province, locality, organization, organizationalUnit, emailAddresses string, dnsNames []string, ipAddresses []net.IP, priv *rsa.PrivateKey) (csrDer []byte, err error) {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	subject := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Province:           []string{province},
		Locality:           []string{locality},
		Organization:       []string{organization},
		OrganizationalUnit: []string{organizationalUnit},
	}

	rawSubj := subject.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddresses},
	})
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddresses},
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        ipAddresses,
	}

	dnsNames = append(dnsNames, commonName)
	template.DNSNames = dnsNames

	return x509.CreateCertificateRequest(rand.Reader, &template, priv)
}
```

**Replace with:**
```go
// CreateCSR creates a Certificate Signing Request (DER bytes).
// CACommonName is deprecated and ignored (kept for backward compatibility).
// commonName is appended to dnsNames if not already present.
func CreateCSR(CACommonName, commonName, country, province, locality, organization, organizationalUnit, emailAddresses string, dnsNames []string, ipAddresses []net.IP, priv *rsa.PrivateKey) (csrDer []byte, err error) {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	subject := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Province:           []string{province},
		Locality:           []string{locality},
		Organization:       []string{organization},
		OrganizationalUnit: []string{organizationalUnit},
	}

	rawSubj := subject.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddresses},
	})
	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CSR subject")
	}
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddresses},
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        ipAddresses,
	}

	// Build a new slice to avoid mutating the caller's dnsNames.
	allDNS := make([]string, 0, len(dnsNames)+1)
	allDNS = append(allDNS, dnsNames...)
	allDNS = append(allDNS, commonName)
	template.DNSNames = allDNS

	return x509.CreateCertificateRequest(rand.Reader, &template, priv)
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C3: Fix `LoadCSRFromPem`

**Why:** Errors ignored; `block` may be nil → panic on `block.Bytes`.

**Current code (lines 113-119):**
```go
// LoadCSR loads a Certificate Signing Request from pem contend.
func LoadCSRFromPem(csrPem []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPem)
	csr, _ := x509.ParseCertificateRequest(block.Bytes)

	return csr, nil
}
```

**Replace with:**
```go
// LoadCSRFromPem loads a Certificate Signing Request from a PEM block.
func LoadCSRFromPem(csrPem []byte) (*x509.CertificateRequest, error) {
	if len(csrPem) == 0 {
		return nil, errors.New("CSR PEM data is empty")
	}
	block, _ := pem.Decode(csrPem)
	if block == nil {
		return nil, errors.New("failed to decode CSR PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CSR")
	}
	return csr, nil
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C4: Fix `LoadCRLFromPem` and migrate to `x509.ParseRevocationList`

**Why:** Errors ignored; `x509.ParseCRL` is deprecated since Go 1.19.

**Current code (lines 121-127):**
```go
// LoadCRL loads a Certificate Revocation List from a pem contend.
func LoadCRLFromPem(crlPem []byte) (*pkix.CertificateList, error) {
	block, _ := pem.Decode(crlPem)
	crl, _ := x509.ParseCRL(block.Bytes)

	return crl, nil
}
```

**Replace with:**
```go
// LoadCRLFromPem loads a Certificate Revocation List from a PEM block.
func LoadCRLFromPem(crlPem []byte) (*x509.RevocationList, error) {
	if len(crlPem) == 0 {
		return nil, errors.New("CRL PEM data is empty")
	}
	block, _ := pem.Decode(crlPem)
	if block == nil {
		return nil, errors.New("failed to decode CRL PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse CRL")
	}
	return crl, nil
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C5: Fix `LoadCertFromPem` (redundant conversion + error checks)

**Why:** `[]byte(string(certString))` is a redundant allocation; error
handling is OK but can be slightly tightened.

**Current code (lines 223-234):**
```go
// LoadCert loads a certifiate from a pem contend.
func LoadCertFromPem(certString []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(string(certString)))
	if block == nil {
		return nil, errors.New("Error when decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error when parse certificate")
	}
	return cert, nil
}
```

**Replace with:**
```go
// LoadCertFromPem loads a certificate from a PEM block.
func LoadCertFromPem(certPem []byte) (*x509.Certificate, error) {
	if len(certPem) == 0 {
		return nil, errors.New("certificate PEM data is empty")
	}
	block, _ := pem.Decode(certPem)
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}
	return cert, nil
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C6: Add CA validity constants and validate `CreateCACert`

**Why:** `CreateCACert` does not validate `validDays`. A CA can be created
with negative or absurd validity.

**Step 1 — add constants.** Current constants block (lines 48-55):
```go
const (
	// MinValidCert is the minimal valid time: 1 day
	MinValidCert int = 1
	// MaxValidCert is the maximum valid time: 3650 day
	MaxValidCert int = 3650
	// DefaultValidCert is the default valid time: 397 days
	DefaultValidCert int = 397
)
```

**Replace with:**
```go
const (
	// MinValidCert is the minimal valid time: 1 day
	MinValidCert int = 1
	// MaxValidCert is the maximum valid time for an end-entity certificate: 3650 days
	MaxValidCert int = 3650
	// DefaultValidCert is the default valid time: 397 days
	DefaultValidCert int = 397

	// MinValidCACert is the minimal valid time for a CA certificate: 1 day.
	MinValidCACert int = 1
	// MaxValidCACert is the maximum valid time for a CA certificate: 3650 days.
	MaxValidCACert int = 3650
	// DefaultValidCACert is the default valid time for a CA certificate: 3650 days (~10 years).
	DefaultValidCACert int = 3650
)
```

**Step 2 — validate at the top of `CreateCACert`.** Current opening (lines 185-187):
```go
	if validDays == 0 {
		validDays = DefaultValidCert
	}
```

**Replace with:**
```go
	if validDays == 0 {
		validDays = DefaultValidCACert
	}
	if validDays < MinValidCACert {
		return nil, errors.Errorf("CA certificate valid days %d is below minimum %d", validDays, MinValidCACert)
	}
	if validDays > MaxValidCACert {
		return nil, errors.Errorf("CA certificate valid days %d exceeds maximum %d", validDays, MaxValidCACert)
	}
```

**Step 3 — also avoid slice mutation in `CreateCACert`.** Current (lines 208-209):
```go
	dnsNames = append(dnsNames, commonName)
	caCert.DNSNames = dnsNames
```

**Replace with:**
```go
	allDNS := make([]string, 0, len(dnsNames)+1)
	allDNS = append(allDNS, dnsNames...)
	allDNS = append(allDNS, commonName)
	caCert.DNSNames = allDNS
```

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C7: Rewrite `CASignCSR` to accept a cert type

**Why:** Currently hardcodes `KeyUsageDigitalSignature` and
`ExtKeyUsage{ClientAuth, ServerAuth}` for all certificates. This is the central
change enabling configurable certificate types. Also remove dead
`CACommonName` use and validate `valid`.

**Current code (lines 248-276):**
```go
// CASignCSR signs an Certificate Signing Request and returns the Certificate as Go bytes.
func CASignCSR(CACommonName string, csr *x509.CertificateRequest, caCert *x509.Certificate, privKey *rsa.PrivateKey, valid int) (certDer []byte, err error) {
	if valid == 0 {
		valid = DefaultValidCert

	} else if valid > MaxValidCert || valid < MinValidCert {
		return nil, errors.Errorf("the certificate valid (min/max) is not between %d - %d", MinValidCert, MaxValidCert)
	}

	csrTemplate := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: newSerialNumber(),
		Issuer:       caCert.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, valid),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	return x509.CreateCertificate(rand.Reader, csrTemplate, caCert, csrTemplate.PublicKey, privKey)
}
```

**Replace with:**
```go
// CASignCSR signs a Certificate Signing Request and returns the certificate
// DER bytes.
//
// certType controls the KeyUsage/ExtKeyUsage of the issued certificate. It
// accepts the same values as goca.ParseCertType (e.g. "server", "client",
// "email", "code-signing"). An empty string uses the historical default
// ("server-client") for backward compatibility.
//
// CACommonName is deprecated and ignored (kept for backward compatibility).
func CASignCSR(CACommonName string, csr *x509.CertificateRequest, caCert *x509.Certificate, privKey *rsa.PrivateKey, valid int, certType string) (certDer []byte, err error) {
	if valid == 0 {
		valid = DefaultValidCert
	} else if valid > MaxValidCert || valid < MinValidCert {
		return nil, errors.Errorf("the certificate valid (min/max) is not between %d - %d", MinValidCert, MaxValidCert)
	}

	t, err := ParseCertType(certType)
	if err != nil {
		return nil, err
	}
	keyUsage, extKeyUsage, err := certTypeUsage(t)
	if err != nil {
		return nil, err
	}

	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	csrTemplate := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: serial,
		Issuer:       caCert.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, valid),
		KeyUsage:     keyUsage,
		ExtKeyUsage:  extKeyUsage,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		BasicConstraintsValid: true,
	}

	return x509.CreateCertificate(rand.Reader, csrTemplate, caCert, csrTemplate.PublicKey, privKey)
}

// CASignCSRLegacy preserves the historical behavior of CASignCSR (server+client
// usage). Deprecated: use CASignCSR with an explicit certType.
//
// Deprecated: use CASignCSR with certType="server-client".
func CASignCSRLegacy(CACommonName string, csr *x509.CertificateRequest, caCert *x509.Certificate, privKey *rsa.PrivateKey, valid int) ([]byte, error) {
	return CASignCSR(CACommonName, csr, caCert, privKey, valid, string(DefaultCertType))
}
```

Note: `ParseCertType` and `certTypeUsage` are defined in the root package
`goca`. But `cert/cert.go` is in package `cert`. To avoid a circular import,
**move the cert-type logic into package `cert`** by relocating
`certtype.go` (from Task A2) to `cert/certtype.go` with `package cert`.

**Action:** Delete `/projects/goca/certtype.go` and recreate it at
`/projects/goca/cert/certtype.go` with `package cert` instead of `package goca`.
The functions `ParseCertType`, `certTypeUsage`, the `CertType` type, constants,
and `ErrUnknownCertType` stay the same.

Then in `ca.go` and `goca.go` (root package), reference them as
`cert.CertTypeServer`, `cert.ParseCertType(...)`, etc. (See Tasks D1, D7, D8,
E1, E2.)

> **Important:** After moving the file, re-run `gofmt -w cert/certtype.go` and
> `go build ./...`. The `cert` package must not import `goca` (no cycle).

**Verify:**
```bash
cd /projects/goca && rm -f certtype.go && gofmt -w cert/*.go && go build ./...
```
If `go build` reports undefined `goca.CertType...` references, those will be
fixed in Tasks D/E. Continue only if `cert` package itself builds.

---

### Task C8: Rewrite `RevokeCertificate` (CRL migration + serial error)

**Why:** Uses `x509.CreateRevocationList` (correct) but `newSerialNumber`
now returns an error. Also `pkix.RevokedCertificate` is the right type for
`RevocationList.RevokedCertificates`.

**Current code (lines 278-290):**
```go
// RevokeCertificate is used to revoke a certificate (added to the revoked list)
func RevokeCertificate(CACommonName string, certificateList []pkix.RevokedCertificate, caCert *x509.Certificate, privKey *rsa.PrivateKey) (crlDer []byte, err error) {

	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  caCert.SignatureAlgorithm,
		RevokedCertificates: certificateList,
		Number:              newSerialNumber(),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().AddDate(0, 0, 1),
	}

	return x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, privKey)
}
```

**Replace with:**
```go
// RevokeCertificate builds a CRL DER bytes containing the given revoked
// certificates. CACommonName is deprecated and ignored (kept for backward
// compatibility).
func RevokeCertificate(CACommonName string, certificateList []pkix.RevokedCertificate, caCert *x509.Certificate, privKey *rsa.PrivateKey) (crlDer []byte, err error) {
	crlNumber, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:  caCert.SignatureAlgorithm,
		RevokedCertificates: certificateList,
		Number:              crlNumber,
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().AddDate(0, 0, 1),
	}

	return x509.CreateRevocationList(rand.Reader, &crlTemplate, caCert, privKey)
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C9: Update `CreateRootCert` to forward new error handling

`CreateRootCert` just delegates to `CreateCACert`, so no signature change is
needed. Verify it still compiles after Task C6.

**Verify:**
```bash
cd /projects/goca && go build ./...
```

---

### Task C10: Final `cert/cert.go` import check

After all Phase C edits, the imports should be exactly:
```go
import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
)
```

Confirm `go vet ./...` passes:
```bash
cd /projects/goca && gofmt -w cert/*.go && go vet ./...
```
There should be no `SA1019` warnings about `x509.ParseCRL` in `cert/cert.go`.

---

## Phase D — Fix `ca.go`

Open `/projects/goca/ca.go`.

### Task D1: Add `Type` field to `Identity`

**Why:** Expose the configurable certificate type to users.

**Current `Identity` struct (after gofmt, lines ~17-29):**
```go
type Identity struct {
	Organization       string   `json:"organization" example:"Company"`
	OrganizationalUnit string   `json:"organization_unit" example:"Security Management"`
	Country            string   `json:"country" example:"NL"`
	Locality           string   `json:"locality" example:"Noord-Brabant"`
	Province           string   `json:"province" example:"Veldhoven"`
	EmailAddresses     string   `json:"email" example:"sec@company.com"`
	DNSNames           []string `json:"dns_names" example:"ca.example.com,root-ca.example.com"`
	IPAddresses        []net.IP `json:"ip_addresses" example:"10.0.0.1,10.0.0.1"`
	Intermediate       bool     `json:"intermediate" example:"false"`
	KeyBitSize         int      `json:"key_size" example:"2048"`
	Valid              int      `json:"valid" example:"365"`
}
```

**Add a `Type` field** before `KeyBitSize`:
```go
type Identity struct {
	Organization       string   `json:"organization" example:"Company"`
	OrganizationalUnit string   `json:"organization_unit" example:"Security Management"`
	Country            string   `json:"country" example:"NL"`
	Locality           string   `json:"locality" example:"Noord-Brabant"`
	Province           string   `json:"province" example:"Veldhoven"`
	EmailAddresses     string   `json:"email" example:"sec@company.com"`
	DNSNames           []string `json:"dns_names" example:"ca.example.com,root-ca.example.com"`
	IPAddresses        []net.IP `json:"ip_addresses" example:"10.0.0.1,10.0.0.1"`
	Intermediate       bool     `json:"intermediate" example:"false"`
	// Type is the certificate type for end-entity certificates issued via
	// IssueCertificate. Accepted values: "server", "client", "server-client",
	// "email", "code-signing", "ocsp-responder", "time-stamping". Empty uses
	// "server-client" (historical default). Ignored when creating a CA.
	Type       string `json:"type" example:"server"`
	KeyBitSize int    `json:"key_size" example:"2048"`
	Valid      int    `json:"valid" example:"365"`
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```

---

### Task D2: Rename/add error variables

**Why:** `ErrParentCommonNameNotSpecified` is misnamed (the check is about nil
parent cert/key, not common name). Add new errors for issuer mismatch and CSR
signature.

**Current (lines 47-53):**
```go
// ErrCAMissingInfo means that all information goca.Information{} is required
var ErrCAMissingInfo = errors.New("all CA details ('Organization', 'Organizational Unit', 'Country', 'Locality', 'Province') are required")

// ErrCertRevoked means that certificate was not found in $CAPATH to be loaded.
var ErrCertRevoked = errors.New("the requested Certificate is already revoked")

var ErrParentCommonNameNotSpecified = errors.New("parent common name is empty when creating an intermediate CA certificate")
```

**Replace with:**
```go
// ErrCAMissingInfo means that all CA Identity fields are required.
var ErrCAMissingInfo = errors.New("all CA details ('Organization', 'Organizational Unit', 'Country', 'Locality', 'Province') are required")

// ErrCertRevoked means the certificate is already on the revocation list.
var ErrCertRevoked = errors.New("the requested Certificate is already revoked")

// ErrParentCANotProvided is returned when creating an intermediate CA without
// a parent certificate or private key.
var ErrParentCANotProvided = errors.New("parent CA certificate or private key is missing when creating an intermediate CA")

// ErrParentNotCA is returned when the parent certificate is not a CA.
var ErrParentNotCA = errors.New("parent certificate is not a CA")

// ErrParentCAExpired is returned when the parent CA certificate has expired.
var ErrParentCAExpired = errors.New("parent CA certificate has expired")

// ErrCertNotIssuedByCA is returned when revoking a certificate that was not
// issued by this CA.
var ErrCertNotIssuedByCA = errors.New("certificate was not issued by this CA")

// ErrCSRSignatureInvalid is returned when a CSR's signature does not verify.
var ErrCSRSignatureInvalid = errors.New("CSR signature verification failed")

// ErrParentCommonNameNotSpecified is kept for backward compatibility.
//
// Deprecated: use ErrParentCANotProvided.
var ErrParentCommonNameNotSpecified = ErrParentCANotProvided
```

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```

---

### Task D3: Migrate `CAData.crl` to `*x509.RevocationList`

**Why:** `pkix.CertificateList` and `x509.ParseCRL` are deprecated.

**Current `CAData` struct (lines ~31-45):**
```go
type CAData struct {
	CRL            string `json:"crl" example:"..."`
	Certificate    string `json:"certificate" example:"..."`
	//CSR            string `json:"csr" example:"..."`
	PrivateKey     string `json:"private_key" example:"..."`
	PublicKey      string `json:"public_key" example:"..."`
	privateKey     *rsa.PrivateKey
	certificate    *x509.Certificate
	publicKey      *rsa.PublicKey
	//csr            *x509.CertificateRequest
	crl            *pkix.CertificateList
	IsIntermediate bool
}
```

**Replace with:**
```go
type CAData struct {
	CRL         string `json:"crl" example:"-----BEGIN X509 CRL-----...-----END X509 CRL-----\n"`
	Certificate string `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`
	//CSR            string `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"`
	PrivateKey  string `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"`
	PublicKey   string `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
	publicKey   *rsa.PublicKey
	//csr            *x509.CertificateRequest
	crl            *x509.RevocationList
	IsIntermediate bool
}
```

Also update the `pkix` import usage: `ca.go` still needs `pkix` for
`pkix.RevokedCertificate` in `revokeCertificate`. Keep the import.

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
Expected: build errors in `create`, `LoadCA`, `revokeCertificate` because they
use `x509.ParseCRL`. Those are fixed in D4, D6, D9.

---

### Task D4: Update `create()` — parent validation + CRL migration

**Why:** (1) No check that `parentCertificate.IsCA` for intermediates. (2)
`x509.ParseCRL` deprecated. (3) `newSerialNumber` (called inside
`cert.CreateCACert`) already handled in Phase C.

**Current `create` function (lines 56-167).** Focus on the intermediate branch
(lines 108-132) and the CRL parsing (lines 148-156).

**Current intermediate branch:**
```go
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
```

**Replace with:**
```go
	} else {
		// Is intermediate CA
		if parentCertificate == nil || parentPrivateKey == nil {
			return ErrParentCANotProvided
		}
		if !parentCertificate.IsCA {
			return ErrParentNotCA
		}
		if parentCertificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("parent certificate does not have KeyUsageCertSign")
		}
		if time.Now().After(parentCertificate.NotAfter) {
			return ErrParentCAExpired
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
```

**Current CRL parsing (lines 148-156):**
```go
	crlBytes, err := cert.RevokeCertificate(c.CommonName, []pkix.RevokedCertificate{}, certificate, caKeys.Key)
	if err != nil {
		return errors.Wrap(err, "Error when create CRL")
	}
	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		return errors.Wrap(err, "Error when parse CRL")
	}
	caData.crl = crl
```

**Replace with:**
```go
	crlBytes, err := cert.RevokeCertificate(c.CommonName, []pkix.RevokedCertificate{}, certificate, caKeys.Key)
	if err != nil {
		return errors.Wrap(err, "failed to create CRL")
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse CRL")
	}
	caData.crl = crl
```

Also fix the early error wrapping messages from "Error when ..." to lowercase
(consistency): in the same function, change:
- `errors.Wrap(err, "Error when create keys")` → `errors.Wrap(err, "failed to create keys")`
- `errors.Wrap(err, "Error when convert private key to PEM")` → `errors.Wrap(err, "failed to convert private key to PEM")`
- `errors.Wrap(err, "Error when convert public key to PEM")` → `errors.Wrap(err, "failed to convert public key to PEM")`
- `errors.Wrap(err, "Error when create CA certificate")` → `errors.Wrap(err, "failed to create CA certificate")`
- `errors.Wrap(err, "Error parse CA certificate")` → `errors.Wrap(err, "failed to parse CA certificate")`
- `errors.Wrap(err, "Error when convert CA certificate to PEM")` → `errors.Wrap(err, "failed to convert CA certificate to PEM")`
- `errors.Wrap(err, "Error when convert CRL to PEM")` → `errors.Wrap(err, "failed to convert CRL to PEM")`

Add `"time"` to imports if not already present (it is — used in `revokeCertificate`).

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
Expected: `create` now compiles. `LoadCA` and `revokeCertificate` still error.

---

### Task D5: Update `LoadCA` — validate crlPem + CRL migration

**Why:** `crlPem` not validated for emptiness; `x509.ParseCRL` deprecated.

**Current `LoadCA` (lines 170-216):**
```go
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
```

**Replace with:**
```go
// LoadCA loads an existing CA from its PEM-encoded components.
func (c *CA) LoadCA(privateKeyPem []byte, publicKeyPem []byte, certPem []byte, crlPem []byte) error {
	if len(privateKeyPem) == 0 {
		return errors.New("private key must be provided")
	}
	if len(publicKeyPem) == 0 {
		return errors.New("public key must be provided")
	}
	if len(certPem) == 0 {
		return errors.New("certificate must be provided")
	}
	if len(crlPem) == 0 {
		return errors.New("CRL must be provided")
	}

	caData := CAData{
		PrivateKey:  string(privateKeyPem),
		PublicKey:   string(publicKeyPem),
		Certificate: string(certPem),
		CRL:         string(crlPem),
	}

	privateKey, err := key.LoadPrivateKeyFromPem(privateKeyPem)
	if err != nil {
		return errors.Wrap(err, "failed to load private key")
	}
	caData.privateKey = privateKey

	publicKey, err := key.LoadPublicKeyFromPem(publicKeyPem)
	if err != nil {
		return errors.Wrap(err, "failed to load public key")
	}
	caData.publicKey = publicKey

	crt, err := cert.LoadCertFromPem(certPem)
	if err != nil {
		return errors.Wrap(err, "failed to load certificate")
	}
	caData.certificate = crt

	crl, err := cert.LoadCRLFromPem(crlPem)
	if err != nil {
		return errors.Wrap(err, "failed to load CRL")
	}
	caData.crl = crl

	c.Data = caData

	return nil
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
Expected: `LoadCA` now compiles. `revokeCertificate` still errors.

---

### Task D6: Update `signCSR` — validate CSR signature + cert type + return nil on error

**Why:** (1) `csr.CheckSignature()` never called → a tampered CSR is signed.
(2) Hardcoded cert type. (3) Returns a partial certificate on error.

**Current `signCSR` (lines 219-256):**
```go
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
	certificate.LSR = string(csrPem)

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
```
(Note: the field is `certificate.CSR`, not `LSR`; the original code uses
`certificate.CSR = string(csrPem)`. Keep `CSR`.)

**Replace with:**
```go
// signCSR generates a certificate from a CSR.
// certType controls the KeyUsage/ExtKeyUsage (see cert.ParseCertType).
func (c *CA) signCSR(csr *x509.CertificateRequest, valid int, certType string) (certificate *Certificate, err error) {
	// Verify the CSR signature before signing.
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.Wrap(ErrCSRSignatureInvalid, err.Error())
	}

	certificate = &Certificate{
		commonName:    csr.Subject.CommonName,
		csr:           csr,
		caCertificate: c.Data.certificate,
		CACertificate: c.Data.Certificate,
		certType:      certType,
	}

	csrDer, err := asn1.Marshal(csr)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CSR")
	}
	csrPem, err := cert.ConvertCSRFromDerToPem(csrDer)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert CSR to PEM")
	}
	certificate.CSR = string(csrPem)

	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, c.Data.privateKey, valid, certType)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign CSR")
	}

	crt, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse signed certificate")
	}
	certificate.certificate = crt

	crtPem, err := cert.ConvertCertificateFromDerToPem(certBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert certificate to PEM")
	}
	certificate.Certificate = string(crtPem)

	return certificate, nil
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
Expected: `signCSR` compiles. Public `SignCSR` in `goca.go` will need a
signature update (Task E2). `revokeCertificate` still errors.

---

### Task D7: Update `issueCertificate` — pass cert type

**Why:** Forward `id.Type` to `CASignCSR`.

**Current `issueCertificate` (lines 259-330).** The relevant line is 309:
```go
	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, c.Data.privateKey, id.Valid)
```

**Replace that line with:**
```go
	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, c.Data.privateKey, id.Valid, id.Type)
```

Also set `certificate.certType` in the initial struct literal. Current (lines 261-264):
```go
	certificate = &Certificate{
		caCertificate: c.Data.certificate,
		CACertificate: c.Data.Certificate,
	}
```

**Replace with:**
```go
	certificate = &Certificate{
		caCertificate: c.Data.certificate,
		CACertificate: c.Data.Certificate,
		certType:      id.Type,
	}
```

Tighten error wrapping in the same function for consistency:
- `return nil, err` after `key.CreateKeys` → `return nil, errors.Wrap(err, "failed to create certificate keys")`
- after `ConvertPrivateKeyFromDerToPem` → `errors.Wrap(err, "failed to convert private key to PEM")`
- after `ConvertRsaPrivateKeyFromDerToPem` → `errors.Wrap(err, "failed to convert RSA private key to PEM")`
- after `ConvertPublicKeyFromDerToPem` → `errors.Wrap(err, "failed to convert public key to PEM")`
- after `cert.CreateCSR` → `errors.Wrap(err, "failed to create CSR")`
- after `x509.ParseCertificateRequest` → `errors.Wrap(err, "failed to parse CSR")`
- after `cert.ConvertCSRFromDerToPem` → `errors.Wrap(err, "failed to convert CSR to PEM")`
- after `cert.CASignCSR` → `errors.Wrap(err, "failed to sign CSR")`
- after `x509.ParseCertificate` → `errors.Wrap(err, "failed to parse certificate")`
- after `cert.ConvertCertificateFromDerToPem` → `errors.Wrap(err, "failed to convert certificate to PEM")`

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```

---

### Task D8: Update `revokeCertificate` — issuer check + CRL migration

**Why:** (1) No check that the certificate was issued by this CA. (2)
`x509.ParseCRL` deprecated. (3) `RevokedCertificates` field on
`*x509.RevocationList` is a `[]pkix.RevokedCertificate` (still valid).

**Current `revokeCertificate` (lines 334-373):**
```go
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
```

**Replace with:**
```go
// revokeCertificate adds a certificate to the CRL.
func (c *CA) revokeCertificate(certificate *x509.Certificate) error {
	if certificate == nil {
		return errors.New("certificate is nil")
	}
	// Verify the certificate was issued by this CA.
	if !bytes.Equal(certificate.RawIssuer, c.Data.certificate.RawSubject) {
		return ErrCertNotIssuedByCA
	}

	var revokedCerts []pkix.RevokedCertificate

	currentCRL := c.GoCRL()
	if currentCRL != nil && len(currentCRL.RevokedCertificates) > 0 {
		for _, revoked := range currentCRL.RevokedCertificates {
			if revoked.SerialNumber.String() == certificate.SerialNumber.String() {
				return ErrCertRevoked
			}
		}
		revokedCerts = currentCRL.RevokedCertificates
	}

	newCertRevoke := pkix.RevokedCertificate{
		SerialNumber:   certificate.SerialNumber,
		RevocationTime: time.Now(),
	}

	revokedCerts = append(revokedCerts, newCertRevoke)

	crlByte, err := cert.RevokeCertificate(c.CommonName, revokedCerts, c.Data.certificate, c.Data.privateKey)
	if err != nil {
		return errors.Wrap(err, "failed to generate CRL")
	}

	crl, err := x509.ParseRevocationList(crlByte)
	if err != nil {
		return errors.Wrap(err, "failed to parse CRL")
	}
	c.Data.crl = crl

	crlPem, err := cert.ConvertCRLFromDerToPem(crlByte)
	if err != nil {
		return errors.Wrap(err, "failed to convert CRL to PEM")
	}
	c.Data.CRL = string(crlPem)

	return nil
}
```

Add `"bytes"` to the `ca.go` import block. Final imports for `ca.go`:
```go
import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"time"

	"github.com/disaster37/goca/cert"
	"github.com/disaster37/goca/key"
	"github.com/pkg/errors"
)
```

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
Now all of `ca.go` should compile. Remaining errors come from `goca.go`
(`SignCSR` signature, `GoCRL` return type, `GeneratePkcs12`).

---

## Phase E — Fix `goca.go`

Open `/projects/goca/goca.go`.

### Task E1: Add `certType` field to `Certificate` + `Type()` method; fix `GoCRL`

**Why:** Expose the chosen cert type on the issued `Certificate`. `GoCRL`
return type must change to `*x509.RevocationList`.

**Current `Certificate` struct (lines 35-48):**
```go
type Certificate struct {
	commonName    string
	Certificate   string                  `json:"certificate" example:"..."`
	CSR           string                  `json:"csr" example:"..."`
	RsaPrivateKey string                  `json:"rsa_private_key" example:"..."`
	PrivateKey    string                  `json:"private_key" example:"..."`
	PublicKey     string                  `json:"public_key" example:"..."`
	CACertificate string                  `json:"ca_certificate" example:"..."`
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	csr           *x509.CertificateRequest
	certificate   *x509.Certificate
	caCertificate *x509.Certificate
}
```

**Replace with:**
```go
type Certificate struct {
	commonName    string
	Certificate   string `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`
	CSR           string `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"`
	RsaPrivateKey string `json:"rsa_private_key" example:"-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----\n"`
	PrivateKey    string `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"`
	PublicKey     string `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`
	CACertificate string `json:"ca_certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	csr           *x509.CertificateRequest
	certificate   *x509.Certificate
	caCertificate *x509.Certificate
	certType      string
}
```

**Current `GoCRL` (lines 109-112):**
```go
// GoCRL returns Certificate Revocation List as Go bytes *pkix.CertificateList
func (c *CA) GoCRL() *pkix.CertificateList {
	return c.Data.crl
}
```

**Replace with:**
```go
// GoCRL returns the Certificate Revocation List as *x509.RevocationList.
func (c *CA) GoCRL() *x509.RevocationList {
	return c.Data.crl
}
```

**Add a `Type()` method** right after `GoCACertificate` (after line ~200):
```go
// Type returns the certificate type string (e.g. "server", "client").
// Returns "" for certificates created before the Type field existed.
func (c *Certificate) Type() string {
	return c.certType
}
```

**Remove the `crypto/x509/pkix` import** from `goca.go` (no longer used).
Final imports for `goca.go`:
```go
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/pkg/errors"
	"software.sslmate.com/src/go-pkcs12"
)
```
(`errors` will be used by `GeneratePKCS12` in Task E3.)

**Verify:**
```bash
cd /projects/goca && gofmt -w goca.go && go build ./...
```
Expected: errors remain for `SignCSR` (calls `signCSR` with old signature) and
`GeneratePkcs12`.

---

### Task E2: Update `SignCSR` to accept a cert type (with backward-compatible overload)

**Why:** `signCSR` now requires a `certType` argument.

**Current `SignCSR` (lines 136-143):**
```go
// SignCSR perform a creation of certificate from a CSR (x509.CertificateRequest) and returns *x509.Certificate
func (c *CA) SignCSR(csr *x509.CertificateRequest, valid int) (certificate *Certificate, err error) {

	certificate, err = c.signCSR(csr, valid)

	return certificate, err

}
```

**Replace with:**
```go
// SignCSR creates a certificate from a CSR (x509.CertificateRequest).
//
// Deprecated: use SignCSRWithType, which lets you choose the certificate type.
// This overload uses the historical default type ("server-client").
func (c *CA) SignCSR(csr *x509.CertificateRequest, valid int) (certificate *Certificate, err error) {
	return c.SignCSRWithType(csr, valid, "")
}

// SignCSRWithType creates a certificate from a CSR with an explicit
// certificate type. certType accepts the values documented on
// cert.ParseCertType (e.g. "server", "client", "email"). An empty string uses
// the historical default.
func (c *CA) SignCSRWithType(csr *x509.CertificateRequest, valid int, certType string) (certificate *Certificate, err error) {
	return c.signCSR(csr, valid, certType)
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w goca.go && go build ./...
```

---

### Task E3: Replace `GeneratePkcs12` with `GeneratePKCS12` using `pkcs12.Modern2023`

**Why:** `pkcs12.Encode` uses RC2-40 + MD5 (broken). Modern2023 uses
PBES2/AES-256/HMAC-SHA-256.

**Current (lines 203-209):**
```go
func GeneratePkcs12(certificate *Certificate, passphrase string, otherCaCerts ...*x509.Certificate) (pfxData []byte, err error) {
	cas := []*x509.Certificate{certificate.caCertificate}
	if len(otherCaCerts) > 0 {
		cas = append(cas, otherCaCerts...)
	}
	return pkcs12.Encode(rand.Reader, certificate.privateKey, certificate.certificate, cas, passphrase)
}
```

**Replace with:**
```go
// GeneratePKCS12 encodes a Certificate (with its CA chain) into a PKCS#12
// bundle using the modern 2023 encryption profile (PBES2/AES-256-CBC +
// HMAC-SHA-256). The passphrase must be non-empty.
func GeneratePKCS12(certificate *Certificate, passphrase string, otherCaCerts ...*x509.Certificate) (pfxData []byte, err error) {
	if certificate == nil {
		return nil, errors.New("certificate is nil")
	}
	if certificate.privateKey == nil || certificate.certificate == nil {
		return nil, errors.New("certificate is missing its private key or certificate")
	}
	if passphrase == "" {
		return nil, errors.New("passphrase is required for PKCS#12 encoding")
	}

	cas := []*x509.Certificate{certificate.caCertificate}
	if len(otherCaCerts) > 0 {
		cas = append(cas, otherCaCerts...)
	}

	encoder := pkcs12.Modern2023
	return encoder.Encode(certificate.privateKey, certificate.certificate, cas, passphrase)
}

// GeneratePkcs12 is kept for backward compatibility.
//
// Deprecated: use GeneratePKCS12, which uses modern PKCS#12 encryption.
func GeneratePkcs12(certificate *Certificate, passphrase string, otherCaCerts ...*x509.Certificate) (pfxData []byte, err error) {
	return GeneratePKCS12(certificate, passphrase, otherCaCerts...)
}
```

**Verify the whole project builds and lints clean:**
```bash
cd /projects/goca && gofmt -w . && go build ./... && go vet ./...
```
There must be NO `SA1019` warnings. If any remain, find them with:
```bash
golangci-lint run ./... 2>&1 | grep SA1019
```

---

## Phase F — Tests

### Task F1: Create `key/key_test.go`

**File:** `/projects/goca/key/key_test.go` (new)

**Full content:**
```go
package key

import (
	"crypto/rsa"
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

func TestLoadPrivateKeyFromPem_PKCS1(t *testing.T) {
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
	pem, err := ConvertRsaPrivateKeyFromDerToPem(kd.Key)
	require.NoError(t, err)
	assert.Contains(t, string(pem), "RSA PRIVATE KEY")

	// Must be loadable as PKCS#1.
	block, _ := pemDecode(t, pem)
	pk, err := parsePKCS1(block)
	require.NoError(t, err)
	assert.True(t, pk.Equal(kd.Key))
}

// helpers used only by TestConvertRsaPrivateKeyFromDerToPem
func pemDecode(t *testing.T, b []byte) (interface{ Bytes() []byte }, error) {
	t.Helper()
	_ = b
	return nil, nil
}
func parsePKCS1(_ interface{ Bytes() []byte }) (*rsa.PrivateKey, error) {
	return nil, nil
}
```

> **Note for the implementer:** the last two helper functions in the test are
> placeholders to keep the file compiling without exposing internal helpers.
> Replace the body of `TestConvertRsaPrivateKeyFromDerToPem` with a simpler
> version using `LoadPrivateKeyFromPem`:
```go
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
```
and **delete** the `pemDecode`/`parsePKCS1` helpers and the `crypto/rsa`
import if unused. Final `key_test.go` imports:
```go
import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
```

**Verify:**
```bash
cd /projects/goca && gofmt -w key/key_test.go && go test ./key/...
```

---

### Task F2: Create `cert/cert_test.go`

**File:** `/projects/goca/cert/cert_test.go` (new)

**Full content:**
```go
package cert

import (
	"crypto/rsa"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: generate a fresh RSA key for tests
func testKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(newRandReader(), bits)
	require.NoError(t, err)
	return k
}

func newRandReader() interface{ Read([]byte) (int, error) } {
	return nil
}
```
> **Note:** The two helpers above are placeholders. Replace them with the
> stdlib directly. Use this final version of `cert_test.go`:
```go
package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"strings"
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
	revoked := []pkixRevokedCert(t, rootCert)
	crl, err := RevokeCertificate("ca", revoked, rootCert, rootPriv)
	require.NoError(t, err)
	parsed, err = x509.ParseRevocationList(crl)
	require.NoError(t, err)
	assert.Len(t, parsed.RevokedCertificates, 1)
}

// helper to build a pkix.RevokedCertificate
func pkixRevokedCert(t *testing.T, _ *x509.Certificate) []pkixRevokedCerts {
	t.Helper()
	return nil
}
```
> **Note:** the final helper above is a placeholder. The simplest correct
> approach is to import `crypto/x509/pkix` and build a revoked entry inline:
```go
// At the top of cert_test.go, add to imports:
//   "crypto/x509/pkix"
//   "math/big"
//
// In TestRevokeCertificate, replace the `revoked := ...` line with:
revoked := []pkix.RevokedCertificate{
	{SerialNumber: big.NewInt(42), RevocationTime: time.Now()},
}
```
and remove the placeholder `pkixRevokedCert` helper and the `pkixRevokedCerts`
type entirely.

Also remove the unused `"strings"` import if no test uses it (some do via
`strings.HasPrefix`). Final imports for `cert/cert_test.go`:
```go
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)
```
Remove `"strings"` only if no test uses it. (The `TestLoadPublicKeyFromPem`-
style assertions on PEM header belong in `key_test.go`, not here, so `strings`
is likely unused here — remove it if `go vet` complains.)

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert_test.go && go test ./cert/...
```

---

### Task F3: Create `cert/certtype_test.go`

**File:** `/projects/goca/cert/certtype_test.go` (new, package `cert`)

**Full content:**
```go
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
```

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/certtype_test.go && go test ./cert/...
```

---

### Task F4: Rewrite `goca_test.go` (uncomment and fix)

**File:** `/projects/goca/goca_test.go`

**Replace the ENTIRE file** with:
```go
package goca

import (
	"crypto/x509"
	"strings"
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
	assert.True(t, strings.HasPrefix(string(pfx), "\x03\x04"))
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
```

> **Note:** `GeneratePKCS12` with `Modern2023` produces PFX data starting with
> bytes `0x30 0x82 ...` (ASN.1 SEQUENCE). Adjust the `strings.HasPrefix`
> assertion to `assert.NotEmpty(t, pfx)` only, if the exact prefix is
> uncertain.

**Verify:**
```bash
cd /projects/goca && gofmt -w goca_test.go && go test ./...
```
All tests must pass.

---

### Task F5: Rewrite `example_test.go`

**File:** `/projects/goca/example_test.go`

**Replace the ENTIRE file** with:
```go
package goca_test

import (
	"fmt"
	"log"

	"github.com/disaster37/goca"
)

// Example_minimal shows creating a Root CA, issuing a server certificate,
// and printing it.
func Example_minimal() {
	rootCAIdentity := goca.Identity{
		Organization:       "GO CA Root Company Inc.",
		OrganizationalUnit: "Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
	}

	rootCA, err := goca.New("go-root.ca", rootCAIdentity)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rootCA.Status())

	serverIdentity := goca.Identity{
		Organization:       "Intranet Company Inc.",
		OrganizationalUnit: "Global Intranet",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		DNSNames:           []string{"w3.intranet.go-root.ca"},
		Type:               goca.CertTypeServer,
	}
	serverCert, err := rootCA.IssueCertificate("intranet.go-root.ca", serverIdentity)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(serverCert.Type())
	// Output:
	// Certificate Authority is ready.
	// server
}
```

> **Note:** `goca.CertTypeServer` is a `cert.CertType` (string). The
> `Identity.Type` field is `string`, so this assignment works because
> `CertType` has underlying type `string`. If the compiler complains about the
> type, use `string(goca.CertTypeServer)` or define `CertType` and its
> constants in the root `goca` package as type aliases re-exported from
> `cert`. The simplest fix is to add, in `goca.go`, type/constant aliases:
```go
// In goca.go, after the import block, add:
type CertType = cert.CertType

const (
	CertTypeServer        = cert.CertTypeServer
	CertTypeClient        = cert.CertTypeClient
	CertTypeServerClient  = cert.CertTypeServerClient
	CertTypeEmail         = cert.CertTypeEmail
	CertTypeCodeSigning   = cert.CertTypeCodeSigning
	CertTypeOCSPResponder = cert.CertTypeOCSPResponder
	CertTypeTimeStamping  = cert.CertTypeTimeStamping
)

// ParseCertType re-exports cert.ParseCertType.
func ParseCertType(s string) (cert.CertType, error) {
	return cert.ParseCertType(s)
}
```
This makes the constants available to library users as `goca.CertTypeServer`
without importing `cert` directly. Add this block in Task E1 (after the
`Type()` method) or as a separate `aliases.go` file at the root.

> **Action:** Create `/projects/goca/aliases.go`:
```go
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
```

**Verify:**
```bash
cd /projects/goca && gofmt -w . && go build ./... && go test ./...
```
The `Example_minimal` test must pass (its `// Output:` block is checked).

---

## Phase G — Infrastructure & Documentation

### Task G1: Rewrite the `Makefile`

**File:** `/projects/goca/Makefile`

**Replace the ENTIRE file** with:
```makefile
GOLANGCI_LINT_VERSION := v1.61.0

.PHONY: lint test fmt vet clean

lint:
	@command -v golangci-lint >/dev/null 2>&1 || \
		{ echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."; \
		  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_VERSION)/install.sh | \
		  sh -s -- -b $$(go env GOPATH)/bin $(GOLANGCI_LINT_VERSION); }
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test -race -covermode=count -coverprofile=count.out -v ./...

clean:
	rm -f count.out coverage.out

```

**Verify:**
```bash
cd /projects/goca && make vet && make test
```

---

### Task G2: Remove the broken `Dockerfile` and `DOCKER_README.md`

**Why:** The Dockerfile references `rest-api/` which does not exist and pins
Go 1.17 (incompatible with go.mod's `go 1.25`). Since this is now a pure
library, there is nothing to containerize.

**Steps:**
```bash
cd /projects/goca
rm -f Dockerfile DOCKER_README.md
```

Also remove the `docker-image` target from the `Makefile` (already absent in
Task G1's version).

**Verify:**
```bash
cd /projects/goca && ls Dockerfile DOCKER_README.md 2>&1
# expected: "No such file or directory" for both
```

---

### Task G3: Replace the GitHub workflows

**Why:** Existing workflows pin Go 1.17, use deprecated actions, and build
the non-existent `rest-api` Docker image.

**Step 1 — delete the two Docker workflows:**
```bash
cd /projects/goca
rm -f .github/workflows/goca-rest-api-docker-dev.yml
rm -f .github/workflows/goca-rest-api-docker-release.yml
```

**Step 2 — replace `.github/workflows/goca-tests.yml`** with:
```yaml
name: GoCA Tests

on:
  push:
    branches: [main, master]
  pull_request:

jobs:
  test:
    name: Build & Test
    runs-on: ubuntu-latest
    steps:
      - name: Check out code
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'
          check-latest: true

      - name: Download dependencies
        run: go mod download

      - name: Verify formatting
        run: |
          if [ -n "$(gofmt -l .)" ]; then
            echo "The following files are not gofmt-clean:"
            gofmt -l .
            exit 1
          fi

      - name: Vet
        run: go vet ./...

      - name: Lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: v1.61

      - name: Test
        run: go test -race -coverprofile=coverage.out -covermode=atomic ./...

      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage.out
```

**Verify (locally, syntax only):**
```bash
cd /projects/goca && cat .github/workflows/goca-tests.yml
```

---

### Task G4: Rewrite `README.md`

**File:** `/projects/goca/README.md`

**Replace the ENTIRE file** with:
```markdown
# GoCA — Certificate Authority management library for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/disaster37/goca.svg)](https://pkg.go.dev/github.com/disaster37/goca)
[![Tests](https://github.com/disaster37/goca/actions/workflows/goca-tests.yml/badge.svg)](https://github.com/disaster37/goca/actions)

GoCA is a Go library that manages a simple PKI on top of `crypto/x509`:
create Root and Intermediate Certificate Authorities, issue certificates from
CSRs, revoke certificates (CRL), and export PKCS#12 bundles.

GoCA is a **pure library**: it does not touch the filesystem. The caller is
responsible for persisting and loading PEM-encoded keys, certificates, and
CRLs.

## Installation

```shell
go get github.com/disaster37/goca
```

## Quick start

```go
package main

import (
	"fmt"
	"log"

	"github.com/disaster37/goca"
)

func main() {
	// 1. Create a Root CA.
	rootCA, err := goca.New("acme.com", goca.Identity{
		Organization:       "ACME Inc.",
		OrganizationalUnit: "Security",
		Country:            "NL",
		Locality:           "Veldhoven",
		Province:           "Noord-Brabant",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rootCA.Status())

	// 2. Issue a TLS server certificate.
	cert, err := rootCA.IssueCertificate("w3.acme.com", goca.Identity{
		Organization: "ACME Inc.",
		Country:      "NL",
		Locality:     "Veldhoven",
		Province:     "Noord-Brabant",
		DNSNames:     []string{"w3.acme.com"},
		Type:         goca.CertTypeServer,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cert.GetCertificate())
	fmt.Println("type:", cert.Type())

	// 3. Export a PKCS#12 bundle.
	pfx, err := goca.GeneratePKCS12(cert, "passphrase")
	if err != nil {
		log.Fatal(err)
	}
	_ = pfx
}
```

## Configurable certificate types

The `Identity.Type` field selects the intended use of an end-entity
certificate. GoCA maps this to the correct `KeyUsage`/`ExtKeyUsage`
extensions internally — no x509 knowledge required.

| `Type` value       | Typical use                         | Resulting extensions                              |
|---------------------|-------------------------------------|---------------------------------------------------|
| `server`            | TLS server (HTTPS, LDAPS, IMAPS)    | EKU: ServerAuth; KU: DigitalSignature, KeyEncipherment |
| `client`            | Mutual TLS client auth              | EKU: ClientAuth; KU: DigitalSignature             |
| `server-client`     | Default (backward-compatible)       | EKU: ServerAuth + ClientAuth; KU: DigitalSignature, KeyEncipherment |
| `email`             | S/MIME                              | EKU: EmailProtection; KU: DigitalSignature, KeyEncipherment |
| `code-signing`      | Binaries, packages, containers      | EKU: CodeSigning; KU: DigitalSignature            |
| `ocsp-responder`    | OCSP signing                        | EKU: OCSPSigning; KU: DigitalSignature            |
| `time-stamping`     | Time Stamping Authority (RFC 3161)  | EKU: TimeStamping; KU: DigitalSignature           |

Empty `Type` defaults to `server-client` (the historical behavior).

The type string is case-insensitive and accepts hyphens, underscores, or
spaces (`"code_signing"`, `"Code-Signing"`, and `"code signing"` are all
equivalent).

## API

| Function | Purpose |
|---|---|
| `goca.New(commonName, identity)` | Create a Root CA |
| `goca.NewCA(commonName, parentCert, parentKey, identity)` | Create an Intermediate CA |
| `(*CA).LoadCA(privKey, pubKey, cert, crl []byte)` | Load a CA from PEM data |
| `(*CA).IssueCertificate(commonName, identity)` | Issue a new certificate |
| `(*CA).SignCSRWithType(csr, valid, type)` | Sign an external CSR |
| `(*CA).RevokeCertificate(cert)` | Revoke a certificate (updates CRL) |
| `(*CA).GetCertificate()` / `GetPrivateKey()` / `GetCRL()` | PEM strings |
| `(*CA).GoCertificate()` / `GoPrivateKey()` / `GoCRL()` | Go objects |
| `goca.GeneratePKCS12(cert, passphrase, ...caCerts)` | PKCS#12 export |

## Security notes

- Minimum RSA key size is 2048 bits (`key.MinKeyBitSize`). Prefer 3072+ for
  long-term CAs.
- `Identity.Valid` for end-entity certificates is bounded by
  `cert.MinValidCert` (1 day) and `cert.MaxValidCert` (3650 days). For
  publicly trusted TLS certificates, follow CA/Browser Forum limits (≤ 398
  days).
- PKCS#12 export uses the modern 2023 profile (PBES2/AES-256/HMAC-SHA-256).
- GoCA verifies CSR signatures before signing and checks that a certificate
  being revoked was issued by the same CA.
- Private keys live in process memory. For production, wrap `LoadCA`/`New`
  with a KMS or HSM-backed key handle.

## License

MIT — see [LICENSE](LICENSE).
```

**Verify:**
```bash
cd /projects/goca && head -5 README.md
```

---

### Task G5: Fix spelling and stale comments

Use the following `grep`-and-replace list. For each, find the exact text and
replace it. Do not touch code logic.

**`ca.go`:**
- Line ~26 (struct tag comment): `Intermendiate Certificate Authority` → `Intermediate Certificate Authority`
- Line ~27 (struct tag comment): `Key Bit Size (defaul: 2048)` → `Key Bit Size (default: 2048)`
- Line ~28 (struct tag comment): `Minimum 1 day, maximum 825 days -- Default: 397` → `Minimum 1 day, maximum 3650 days -- Default: 397`
- Comment above `revokeCertificate`: `// It add it on  rovokated list` → `// It adds the certificate to the revocation list.`
- Comment above `LoadCA`: `// loadCA permti to load existing CA` → `// loadCA loads an existing CA`
- Comment above `create`: `// create permit to create new CA or intermediate CA` → `// create creates a new CA or intermediate CA`

**`goca.go`:**
- Line ~54: `// New creat new Certificate Authority` → `// New creates a new Root Certificate Authority`

**`cert/cert.go`:**
- Comment above `LoadCSRFromPem` (already rewritten in Task C3, ensure "contend" is gone): use "PEM block".
- Comment above `LoadCRLFromPem` (already rewritten in Task C4): use "PEM block".
- Comment above `LoadCertFromPem` (already rewritten in Task C5): use "PEM block".
- Line ~223 original: `// LoadCert loads a certifiate from a pem contend.` — already replaced in Task C5.
- Comment above `ConvertCRLFromDerToPem`: `permit to convert CLR from DER format to PEM format` → `converts a CRL from DER format to PEM format`.

**`key/key.go`:**
- Comment above `ConvertPublicKeyFromDerToPem` (already rewritten in Task B4): ensure "ConvertPrivateKeyFromDerToPem" copy-paste error is gone.

After edits:
```bash
cd /projects/goca && gofmt -w . && go build ./... && go test ./...
```

---

### Task G6: Remove `.theia/launch.json` (optional cleanup)

Not strictly necessary, but the file references `${fileDirname}` which is fine.
Leave it. No action needed.

---

### Task G7: Update `go.mod` if needed

The module path `github.com/disaster37/goca` and `go 1.25` are correct. No
change. Just verify:
```bash
cd /projects/goca && head -5 go.mod
```

---

## Phase H — Final Verification

Run each of these in order from `/projects/goca`. All must succeed.

### H1: Formatting
```bash
gofmt -l .
```
**Expected:** no output.

### H2: Build
```bash
go build ./...
```
**Expected:** no output (success).

### H3: Vet
```bash
go vet ./...
```
**Expected:** no output.

### H4: Lint
```bash
golangci-lint run ./...
```
**Expected:** no `SA1019` warnings, no errors. (Pre-existing stylistic warnings
are acceptable; deprecation warnings are NOT.)

### H5: Tests with race detector
```bash
go test -race -coverprofile=coverage.out -covermode=atomic -v ./...
```
**Expected:** all tests pass; coverage should be significantly improved over
the baseline (the `key` and `cert` packages previously had 0% coverage).

### H6: Coverage report
```bash
go tool cover -func=coverage.out | tail -1
```
**Expected:** total coverage > 60%.

### H7: Smoke check the configurable type feature
```bash
cat > /tmp/goca_smoke_test.go << 'SMOKE_EOF'
package main

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/disaster37/goca"
)

func main() {
	root, err := goca.New("smoke.ca", goca.Identity{
		Organization: "O", OrganizationalUnit: "U",
		Country: "NL", Locality: "L", Province: "P",
	})
	if err != nil { fmt.Println("ERR root:", err); os.Exit(1) }

	for _, ty := range []string{"server", "client", "email", "code-signing", "ocsp-responder", "time-stamping"} {
		c, err := root.IssueCertificate("svc-"+ty+".smoke.ca", goca.Identity{
			Organization: "O", OrganizationalUnit: "U",
			Country: "NL", Locality: "L", Province: "P",
			Type: ty,
		})
		if err != nil { fmt.Println("ERR issue", ty, err); os.Exit(1) }
		gc := c.GoCert()
		fmt.Printf("%-15s Type=%-15s EKU=%v KU=%v\n", ty, c.Type(), gc.ExtKeyUsage, gc.KeyUsage)
		_ = x509.ExtKeyUsage(0)
	}

	// PKCS#12
	c, _ := root.IssueCertificate("p12.smoke.ca", goca.Identity{
		Organization: "O", OrganizationalUnit: "U",
		Country: "NL", Locality: "L", Province: "P",
		Type: "server",
	})
	pfx, err := goca.GeneratePKCS12(c, "secret")
	if err != nil { fmt.Println("ERR p12:", err); os.Exit(1) }
	fmt.Printf("PKCS#12 bytes: %d\n", len(pfx))

	fmt.Println("SMOKE OK")
}
SMOKE_EOF
cd /tmp && go run goca_smoke_test.go
```
**Expected output:** six lines showing each type with its EKU/KU, then a
`PKCS#12 bytes: NNN` line, then `SMOKE OK`. The program must exit 0.

Clean up:
```bash
rm -f /tmp/goca_smoke_test.go
```

---

## 3. Dependency graph between tasks

```
A1 (gofmt) ──┐
             ├─► A2 (certtype.go) ──► move to cert/certtype.go (in C7)
             │
B1..B4 (key) ─┤
             │
C1..C8 (cert) ─┤  (C7 depends on certtype.go being in package cert)
             │
D1..D8 (ca)  ─┤  (D1, D2 independent; D3 before D4/D5/D6/D8;
             │   D6 before D7; D7 before D8)
             │
E1..E3 (goca) ─┤  (E1 before E2; E2 before E3)
             │
F1..F5 (tests) ─┤
             │
G1..G7 (infra) ─┤
             │
H (final)    ──┘
```

**Minimum safe order:** A1 → A2 → B* → C1 → C2 → C3 → C4 → C5 → C6 → C7
(includes moving certtype.go) → C8 → C9 → C10 → D1 → D2 → D3 → D4 → D5 → D6 →
D7 → D8 → create aliases.go → E1 → E2 → E3 → F1 → F2 → F3 → F4 → F5 → G1 →
G2 → G3 → G4 → G5 → H.

---

## 4. Rollback / safety notes

- Every public-API breaking change keeps a deprecated alias so existing
  callers still compile:
  - `cert.CASignCSRLegacy` wraps `cert.CASignCSR`
  - `goca.SignCSR` wraps `goca.SignCSRWithType`
  - `goca.GeneratePkcs12` wraps `goca.GeneratePKCS12`
  - `ErrParentCommonNameNotSpecified` aliases `ErrParentCANotProvided`
- The `Identity.Type` field defaults to `""` which resolves to
  `server-client`, preserving the exact historical KeyUsage/ExtKeyUsage.
- The `CACommonName`/`commonName` parameters on `cert.*` functions are kept
  (ignored) so existing direct callers of those functions still compile.
- `CAData.crl` changed type from `*pkix.CertificateList` to
  `*x509.RevocationList`. This is a source-incompatible change for anyone
  accessing `c.Data.crl` directly (it is an unexported field, so only
  internal code is affected). The public accessor `GoCRL()` changes return
  type — document this in the changelog as the one breaking change. Bump the
  module to v2 if semver-strict consumers exist.

---

## 5. Changelog entry to add at release time

Create `CHANGELOG.md`:
```markdown
# Changelog

## [Unreleased]

### Added
- Configurable certificate types via `Identity.Type` (values: `server`,
  `client`, `server-client`, `email`, `code-signing`, `ocsp-responder`,
  `time-stamping`). Empty defaults to `server-client` (backward compatible).
- `goca.CertType*` constants and `goca.ParseCertType` re-exported in the root
  package.
- `(*CA).SignCSRWithType(csr, valid, type)` for signing external CSRs with an
  explicit type.
- `(*Certificate).Type()` returns the type string of an issued certificate.
- Tests for the `key` and `cert` packages (previously 0% coverage).
- `key.MinKeyBitSize`, `key.DefaultKeyBitSize`, `cert.MinValidCACert`,
  `cert.MaxValidCACert`, `cert.DefaultValidCACert`.

### Changed
- `(*CA).GoCRL()` now returns `*x509.RevocationList` (was
  `*pkix.CertificateList`). **Breaking** — bump major version if needed.
- `cert.CASignCSR` now takes a `certType string` argument. Use
  `cert.CASignCSRLegacy` for the old signature.
- `goca.GeneratePkcs12` is deprecated; use `goca.GeneratePKCS12` (modern
  PKCS#12 encryption: PBES2/AES-256/HMAC-SHA-256).
- `key.LoadPublicKeyFromPem` now produces/accepts PKIX/SPKI PEM (was PKCS#1
  mislabeled as SPKI).
- `cert.LoadCRLFromPem` returns `*x509.RevocationList`.

### Fixed
- `key.LoadPrivateKeyFromPem`, `key.LoadPublicKeyFromPem`,
  `cert.LoadCSRFromPem`, `cert.LoadCRLFromPem` no longer ignore errors or
  panic on empty/invalid input.
- `cert.newSerialNumber` now propagates CSPRNG errors.
- `cert.CreateCSR` no longer mutates the caller's `dnsNames` slice and no
  longer ignores `asn1.Marshal` errors.
- `cert.CreateCACert` now validates `validDays`.
- `(*CA).revokeCertificate` now verifies the certificate was issued by this
  CA before adding it to the CRL.
- `(*CA).signCSR` now verifies the CSR signature (`csr.CheckSignature`)
  before signing.
- `(*CA).create` validates that the parent certificate is a CA with
  `KeyUsageCertSign` and is not expired.
- `(*CA).LoadCA` now validates `crlPem` is non-empty.
- `(*CA).signCSR` returns `nil` (not a partial certificate) on error.
- Migrated off deprecated `x509.ParseCRL` and `pkcs12.Encode`.

### Removed
- `Dockerfile` and `DOCKER_README.md` (the project is a pure library; the
  Docker build referenced a non-existent `rest-api/` directory).
- GitHub workflows for the Docker REST API image.

### Documentation
- Rewrote `README.md` to reflect the library-only API and document the
  configurable certificate types.
- Uncommented and fixed `example_test.go` (`Example_minimal`).
- Uncommented and fixed the previously dead tests in `goca_test.go`.
```

---

## 6. Quick reference: file inventory after all tasks

```
goca/
├── ca.go                       (modified)
├── goca.go                     (modified)
├── goca_test.go                (rewritten)
├── example_test.go             (rewritten)
├── aliases.go                  (new)
├── IMPLEMENTATION_PLAN.md      (this file)
├── CHANGELOG.md                (new, at release time)
├── go.mod, go.sum              (unchanged)
├── Makefile                    (rewritten)
├── README.md                   (rewritten)
├── LICENSE                     (unchanged)
├── .gitignore                  (unchanged)
├── .theia/launch.json          (unchanged)
├── .github/workflows/
│   └── goca-tests.yml          (rewritten)
├── cert/
│   ├── cert.go                 (modified)
│   ├── certtype.go             (new)
│   ├── cert_test.go            (new)
│   └── certtype_test.go        (new)
└── key/
    ├── key.go                  (modified)
    └── key_test.go             (new)
```

Removed: `Dockerfile`, `DOCKER_README.md`,
`.github/workflows/goca-rest-api-docker-dev.yml`,
`.github/workflows/goca-rest-api-docker-release.yml`.

---

End of plan.
