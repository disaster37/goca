# GoCA — Self-Contained Implementation Plan

A complete, task-by-task plan to fix bugs, add configurable certificate types,
and modernize the `goca` Go PKI library (`github.com/disaster37/goca`, Go 1.25).

Every task includes exact code, file paths, imports, and verification commands.
No external references needed.

---

## Table of Contents

1. [Project Layout & Conventions](#1-project-layout--conventions)
2. [Phase A — Formatting & New Files](#phase-a--formatting--new-files)
   - [Task A1: gofmt all files](#task-a1-gofmt-all-files)
   - [Task A2: Create `cert/certtype.go`](#task-a2-create-certcerttypego)
3. [Phase B — Fix `key/key.go`](#phase-b--fix-keykeygo)
   - [Task B1: Validate `CreateKeys` + add constants](#task-b1-validate-createkeys--add-constants)
   - [Task B2: Fix `LoadPrivateKeyFromPem`](#task-b2-fix-loadprivatekeyfrompem)
   - [Task B3: Fix `LoadPublicKeyFromPem`](#task-b3-fix-loadpublickeyfrompem)
   - [Task B4: Fix `ConvertPublicKeyFromDerToPem`](#task-b4-fix-convertpublickeyfromdertopem)
4. [Phase C — Fix `cert/cert.go`](#phase-c--fix-certcertgo)
   - [Task C1: Fix `newSerialNumber`](#task-c1-fix-newserialnumber)
   - [Task C2: Fix `CreateCSR`](#task-c2-fix-createcsr)
   - [Task C3: Fix `LoadCSRFromPem`](#task-c3-fix-loadcsrfrompem)
   - [Task C4: Fix `LoadCRLFromPem`](#task-c4-fix-loadcrlfrompem)
   - [Task C5: Fix `LoadCertFromPem`](#task-c5-fix-loadcertfrompem)
   - [Task C6: Validate `CreateCACert` + add CA constants](#task-c6-validate-createcacert--add-ca-constants)
   - [Task C7: Rewrite `CASignCSR` with cert type](#task-c7-rewrite-casigncsr-with-cert-type)
   - [Task C8: Fix `RevokeCertificate`](#task-c8-fix-revokecertificate)
   - [Task C9: Update `CreateRootCert`](#task-c9-update-createrootcert)
   - [Task C10: Final import check](#task-c10-final-import-check-for-certcertgo)
5. [Phase D — Fix `ca.go`](#phase-d--fix-cago)
   - [Task D1: Add `Type` field to `Identity`](#task-d1-add-type-field-to-identity)
   - [Task D2: Rename/add error variables](#task-d2-renameadd-error-variables)
   - [Task D3: Migrate `CAData.crl` to `*x509.RevocationList`](#task-d3-migrate-cadatacrl-to-x509revocationlist)
   - [Task D4: Update `create()` — parent validation + CRL migration](#task-d4-update-create---parent-validation--crl-migration)
   - [Task D5: Update `LoadCA`](#task-d5-update-loadca)
   - [Task D6: Update `signCSR`](#task-d6-update-signcsr)
   - [Task D7: Update `issueCertificate`](#task-d7-update-issuecertificate)
   - [Task D8: Update `revokeCertificate`](#task-d8-update-revokecertificate)
6. [Phase E — Fix `goca.go` + Create `aliases.go`](#phase-e--fix-gocago--create-aliasesgo)
   - [Task E1: Add `certType` to `Certificate`, fix `GoCRL`, add `Type()` method](#task-e1-add-certtype-to-certificate-fix-gocrl-add-type-method)
   - [Task E2: Update `SignCSR` overloads](#task-e2-update-signcsr-overloads)
   - [Task E3: Replace `GeneratePkcs12` with `GeneratePKCS12`](#task-e3-replace-generatepkcs12-with-generatepkcs12)
   - [Task E4: Create `aliases.go`](#task-e4-create-aliasesgo)
7. [Phase F — Tests](#phase-f--tests)
   - [Task F1: Create `key/key_test.go`](#task-f1-create-keykey_testgo)
   - [Task F2: Create `cert/cert_test.go`](#task-f2-create-certcert_testgo)
   - [Task F3: Create `cert/certtype_test.go`](#task-f3-create-certcerttype_testgo)
   - [Task F4: Rewrite `goca_test.go`](#task-f4-rewrite-goca_testgo)
   - [Task F5: Rewrite `example_test.go`](#task-f5-rewrite-example_testgo)
8. [Phase G — Infrastructure](#phase-g--infrastructure)
   - [Task G1: Rewrite `Makefile`](#task-g1-rewrite-makefile)
   - [Task G2: Remove Docker files](#task-g2-remove-docker-files)
   - [Task G3: Replace GitHub workflows](#task-g3-replace-github-workflows)
   - [Task G4: Rewrite `README.md`](#task-g4-rewrite-readmemd)
   - [Task G5: Fix spelling and stale comments](#task-g5-fix-spelling-and-stale-comments)
9. [Phase H — Final Verification](#phase-h--final-verification)
10. [Dependency Graph](#dependency-graph)
11. [Backward Compatibility Summary](#backward-compatibility-summary)
12. [File Inventory After All Tasks](#file-inventory-after-all-tasks)

---

## 1. Project Layout & Conventions

### Current file layout

```
goca/
├── ca.go              # CA logic: create/load/sign/issue/revoke
├── goca.go            # Public API: New, NewCA, IssueCertificate, SignCSR, GeneratePkcs12
├── goca_test.go       # Tests (partially commented out)
├── example_test.go    # Example (fully commented out)
├── cert/cert.go       # Certificate/CSR/CRL generation and conversion
├── key/key.go         # RSA key generation and loading
├── go.mod, go.sum
├── Makefile, Dockerfile, DOCKER_README.md
├── README.md
└── .github/workflows/
    ├── goca-tests.yml
    ├── goca-rest-api-docker-dev.yml
    └── goca-rest-api-docker-release.yml
```

### Conventions

1. **Read the file before editing.** Confirm "Current code" matches.
2. **One task at a time.** Do not combine unrelated tasks.
3. **Run `gofmt -w <file>` after every Go file edit.**
4. **Run `go build ./...` after each phase.** It must succeed.
5. **Run `go test ./...` after Phase F.** All tests must pass.
6. **Never change a public function signature without keeping a deprecated alias.**
7. **Preserve MIT license headers** in `cert/cert.go` (lines 1-21) and `key/key.go` (lines 1-21).
8. **Error wrapping:** use `github.com/pkg/errors` — `errors.Wrap(err, "msg")`, `errors.New("msg")`, `errors.Errorf("...", args)`.
9. **Imports:** stdlib first, then third-party, grouped with blank lines.
10. **Module path:** `github.com/disaster37/goca`, Go 1.25.

### Baseline verification (run first)

```bash
cd /projects/goca
go version          # must be >= 1.25
go build ./...      # must succeed (baseline)
go test ./...       # baseline: 3 tests pass
```

---

## Phase A — Formatting & New Files

### Task A1: gofmt all files

**Files:** `ca.go`, `goca.go`, `goca_test.go`, `example_test.go`, `key/key.go`, `cert/cert.go`

**Action:**
```bash
cd /projects/goca
gofmt -w ca.go goca.go goca_test.go example_test.go key/key.go cert/cert.go
```

**Verify:**
```bash
gofmt -l .
# Expected: no output
```

---

### Task A2: Create `cert/certtype.go`

**File:** `/projects/goca/cert/certtype.go` (NEW)

**Why:** Defines `CertType` enum with human-readable names mapped to `x509.KeyUsage`/`ExtKeyUsage`. Lives in package `cert` to avoid circular imports (root `goca` imports `cert`; `cert` must not import `goca`).

**Full file content:**

```go
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
```

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/certtype.go && go build ./...
```

---

## Phase B — Fix `key/key.go`

Preserve MIT license header (lines 1-21) unchanged throughout.

### Task B1: Validate `CreateKeys` + add constants

**File:** `/projects/goca/key/key.go`

**Current imports (lines 32-39):**
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

**Replace imports with:**
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

**Edge cases handled:**
- `bitSize == 0` → uses `DefaultKeyBitSize` (2048)
- `bitSize < 2048` → returns `ErrKeyBitSizeTooSmall`
- `bitSize % 8 != 0` → returns error (RSA requires byte-aligned sizes)

**Verify:**
```bash
cd /projects/goca && gofmt -w key/key.go && go build ./...
```

---

### Task B2: Fix `LoadPrivateKeyFromPem`

**File:** `/projects/goca/key/key.go`

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

**Edge cases handled:**
- `keyPem` is empty or nil → error
- PEM decode fails → error (no nil panic)
- Parse fails (corrupt data) → wrapped error
- Non-RSA key in PKCS#8 block → error
- Unknown block type → error

**Verify:**
```bash
cd /projects/goca && gofmt -w key/key.go && go build ./...
```

---

### Task B3: Fix `LoadPublicKeyFromPem`

**File:** `/projects/goca/key/key.go`

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

**Edge cases handled:**
- `keyPem` is empty or nil → error
- PEM decode fails → error
- PKIX parse fails → wrapped error
- PKIX key is not RSA → error
- PKCS#1 parse fails → wrapped error
- Unknown block type → error

**Verify:**
```bash
cd /projects/goca && gofmt -w key/key.go && go build ./...
```

---

### Task B4: Fix `ConvertPublicKeyFromDerToPem`

**File:** `/projects/goca/key/key.go`

**Why:** Uses `asn1.Marshal(*publicKey)` (produces PKCS#1 bytes) but labels as `"PUBLIC KEY"` (PKIX). This mismatch breaks parsers. Fix to use `x509.MarshalPKIXPublicKey`. Also remove `encoding/asn1` import.

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

**Then remove `encoding/asn1` from imports.** Final imports for `key/key.go`:
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

Preserve MIT license header (lines 1-21) unchanged throughout.

### Task C1: Fix `newSerialNumber`

**File:** `/projects/goca/cert/cert.go`

**Why:** `rand.Int` error is ignored; if CSPRNG fails, serial is nil → invalid cert (RFC 5280 requires positive integer).

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

**Then update all call sites:**

1. In `CreateCACert` (line 189): Change `SerialNumber: newSerialNumber(),` to use the new error-returning form. Insert BEFORE the struct literal:
```go
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
```
Then change `SerialNumber: newSerialNumber(),` to `SerialNumber: serial,`.

2. In `CASignCSR` (line 264): Same pattern — handled in Task C7 which rewrites the whole function.

3. In `RevokeCertificate` (line 284): Same pattern — handled in Task C8 which rewrites the whole function.

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```
**Expected:** `CreateCACert` compiles. `CASignCSR` and `RevokeCertificate` still reference old `newSerialNumber()` — will be fixed in C7/C8.

---

### Task C2: Fix `CreateCSR`

**File:** `/projects/goca/cert/cert.go`

**Why:** `asn1.Marshal` error ignored; `dnsNames = append(dnsNames, commonName)` mutates the caller's slice.

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

**Edge cases handled:**
- `asn1.Marshal` error → wrapped and returned (not ignored)
- Caller's `dnsNames` slice is never mutated (new slice created)

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C3: Fix `LoadCSRFromPem`

**File:** `/projects/goca/cert/cert.go`

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

**Edge cases:** empty input, nil block, parse failure → all return errors.

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C4: Fix `LoadCRLFromPem`

**File:** `/projects/goca/cert/cert.go`

**Why:** `x509.ParseCRL` deprecated since Go 1.19; migrate to `x509.ParseRevocationList`.

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

**Breaking change:** Return type changes from `*pkix.CertificateList` to `*x509.RevocationList`. All callers in `ca.go` must be updated (Tasks D3-D5, D8).

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```
**Expected:** `cert` package builds. `ca.go` will have compilation errors (fixed in Phase D).

---

### Task C5: Fix `LoadCertFromPem`

**File:** `/projects/goca/cert/cert.go`

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

**Changes:** Removes redundant `[]byte(string(...))` conversion; adds empty-input check; standardizes error messages.

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C6: Validate `CreateCACert` + add CA constants

**File:** `/projects/goca/cert/cert.go`

**Step 1 — Replace constants block (lines 48-55):**

**Current:**
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
	// MinValidCert is the minimal valid time for end-entity certificates: 1 day.
	MinValidCert int = 1
	// MaxValidCert is the maximum valid time for end-entity certificates: 3650 days.
	MaxValidCert int = 3650
	// DefaultValidCert is the default valid time for end-entity certificates: 397 days.
	DefaultValidCert int = 397

	// MinValidCACert is the minimal valid time for a CA certificate: 1 day.
	MinValidCACert int = 1
	// MaxValidCACert is the maximum valid time for a CA certificate: 3650 days.
	MaxValidCACert int = 3650
	// DefaultValidCACert is the default valid time for a CA certificate: 3650 days (~10 years).
	DefaultValidCACert int = 3650
)
```

**Step 2 — Validate `validDays` in `CreateCACert`.**

**Current opening (lines 185-187):**
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

**Step 3 — Fix DNS slice mutation (lines 208-209).**

**Current:**
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

**Step 4 — Fix `newSerialNumber()` call (line 189).**

In `CreateCACert`, BEFORE the `caCert := &x509.Certificate{` literal, add:
```go
	serial, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
```
Then change `SerialNumber: newSerialNumber(),` to `SerialNumber: serial,`.

**Edge cases handled:**
- `validDays == 0` → uses `DefaultValidCACert` (3650)
- `validDays < 1` → error
- `validDays > 3650` → error
- Caller's `dnsNames` slice not mutated
- Serial generation failure → propagated error

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```

---

### Task C7: Rewrite `CASignCSR` with cert type

**File:** `/projects/goca/cert/cert.go`

**Why:** Central change enabling configurable certificate types. Currently hardcodes `KeyUsageDigitalSignature` and `ExtKeyUsage{ClientAuth, ServerAuth}` for all certs.

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
// accepts the same values as ParseCertType (e.g. "server", "client",
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

**Breaking change:** `CASignCSR` signature gains a `certType string` parameter. `CASignCSRLegacy` provides the old signature for backward compatibility.

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert.go && go build ./...
```
**Expected:** `cert` package builds. `ca.go` will have compilation errors (callers need `certType` argument — fixed in Phase D).

---

### Task C8: Fix `RevokeCertificate`

**File:** `/projects/goca/cert/cert.go`

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

### Task C9: Update `CreateRootCert`

**File:** `/projects/goca/cert/cert.go`

`CreateRootCert` delegates to `CreateCACert`. No signature change needed — just verify it still compiles after Task C6.

**Verify:**
```bash
cd /projects/goca && go build ./...
```

---

### Task C10: Final import check for `cert/cert.go`

After all Phase C edits, verify imports are exactly:
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

Run:
```bash
cd /projects/goca && gofmt -w cert/*.go && go vet ./...
```
**Expected:** no `SA1019` warnings about `x509.ParseCRL`.

---

## Phase D — Fix `ca.go`

### Task D1: Add `Type` field to `Identity`

**File:** `/projects/goca/ca.go`

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

**Add `Type` field before `KeyBitSize`:**
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

**File:** `/projects/goca/ca.go`

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

**File:** `/projects/goca/ca.go`

**Current `CAData` struct (lines 33-45):**
```go
type CAData struct {
	CRL            string `json:"crl" example:"-----BEGIN X509 CRL-----...-----END X509 CRL-----\n"`
	Certificate    string `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`
	//CSR            string `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"`
	PrivateKey     string `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"`
	PublicKey      string `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`
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

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
**Expected:** build errors in `create`, `LoadCA`, `revokeCertificate` (they use `x509.ParseCRL` and access `TBSCertList`). Fixed in D4, D5, D8.

---

### Task D4: Update `create()` — parent validation + CRL migration

**File:** `/projects/goca/ca.go`

**Part 1 — Parent validation in intermediate branch (lines 108-132).**

**Current:**
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

**Part 2 — CRL parsing (lines 148-156).**

**Current:**
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

**Part 3 — Fix error wrapping messages (lowercase, consistent).** Replace all in `create()`:
- `errors.Wrap(err, "Error when create keys")` → `errors.Wrap(err, "failed to create keys")`
- `errors.Wrap(err, "Error when convert private key to PEM")` → `errors.Wrap(err, "failed to convert private key to PEM")`
- `errors.Wrap(err, "Error when convert public key to PEM")` → `errors.Wrap(err, "failed to convert public key to PEM")`
- `errors.Wrap(err, "Error when create CA certificate")` → `errors.Wrap(err, "failed to create CA certificate")`
- `errors.Wrap(err, "Error parse CA certificate")` → `errors.Wrap(err, "failed to parse CA certificate")`
- `errors.Wrap(err, "Error when convert CA certificate to PEM")` → `errors.Wrap(err, "failed to convert CA certificate to PEM")`
- `errors.Wrap(err, "Error when convert CRL to PEM")` → `errors.Wrap(err, "failed to convert CRL to PEM")`

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
**Expected:** `create` compiles. `LoadCA` and `revokeCertificate` still error.

---

### Task D5: Update `LoadCA`

**File:** `/projects/goca/ca.go`

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

**Edge case:** `crlPem` empty is now validated (was silently accepted before).

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
**Expected:** `LoadCA` compiles. `revokeCertificate` still errors.

---

### Task D6: Update `signCSR`

**File:** `/projects/goca/ca.go`

**Why:** Add CSR signature verification, cert type parameter, return nil on error.

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
	certificate.CSR = string(csrPem)

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

**Key changes:**
- Adds `certType string` parameter
- Adds `csr.CheckSignature()` verification
- Returns `nil` (not partial certificate) on `CASignCSR` error
- Wraps all errors with context

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
**Expected:** `signCSR` compiles. `SignCSR` in `goca.go` will need update (Task E2). `revokeCertificate` still errors.

---

### Task D7: Update `issueCertificate`

**File:** `/projects/goca/ca.go`

**Part 1 — Forward cert type to `CASignCSR` (line 309).**

**Current:**
```go
	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, c.Data.privateKey, id.Valid)
```

**Replace with:**
```go
	certBytes, err := cert.CASignCSR(c.CommonName, csr, c.Data.certificate, c.Data.privateKey, id.Valid, id.Type)
```

**Part 2 — Set `certType` in Certificate struct (lines 261-264).**

**Current:**
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

**Part 3 — Tighten error wrapping in `issueCertificate`.** Replace all bare `return nil, err` with wrapped versions:
- After `key.CreateKeys` → `return nil, errors.Wrap(err, "failed to create certificate keys")`
- After `key.ConvertPrivateKeyFromDerToPem` → `return nil, errors.Wrap(err, "failed to convert private key to PEM")`
- After `key.ConvertRsaPrivateKeyFromDerToPem` → `return nil, errors.Wrap(err, "failed to convert RSA private key to PEM")`
- After `key.ConvertPublicKeyFromDerToPem` → `return nil, errors.Wrap(err, "failed to convert public key to PEM")`
- After `cert.CreateCSR` → `return nil, errors.Wrap(err, "failed to create CSR")`
- After `x509.ParseCertificateRequest` → `return nil, errors.Wrap(err, "failed to parse CSR")`
- After `cert.ConvertCSRFromDerToPem` → `return nil, errors.Wrap(err, "failed to convert CSR to PEM")`
- After `cert.CASignCSR` → `return nil, errors.Wrap(err, "failed to sign CSR")`
- After `x509.ParseCertificate` → `return nil, errors.Wrap(err, "failed to parse certificate")`
- After `cert.ConvertCertificateFromDerToPem` → `return nil, errors.Wrap(err, "failed to convert certificate to PEM")`

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```

---

### Task D8: Update `revokeCertificate`

**File:** `/projects/goca/ca.go`

**Why:** Add issuer check; migrate from `x509.ParseCRL` to `x509.ParseRevocationList`; access `RevokedCertificates` on `*x509.RevocationList`.

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

**Add `"bytes"` to imports** if not present. Final imports for `ca.go`:
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

**Edge cases handled:**
- `certificate` is nil → error
- Certificate not issued by this CA → `ErrCertNotIssuedByCA`
- Certificate already in CRL → `ErrCertRevoked`
- Empty CRL → creates new one

**Verify:**
```bash
cd /projects/goca && gofmt -w ca.go && go build ./...
```
**Expected:** All of `ca.go` compiles. Remaining errors come from `goca.go` (`SignCSR` signature, `GoCRL` return type, `GeneratePkcs12`).

---

## Phase E — Fix `goca.go` + Create `aliases.go`

### Task E1: Add `certType` to `Certificate`, fix `GoCRL`, add `Type()` method

**File:** `/projects/goca/goca.go`

**Part 1 — Add `certType` field to `Certificate` struct (lines 35-48).**

**Current:**
```go
type Certificate struct {
	commonName    string
	Certificate   string                  `json:"certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`
	CSR           string                  `json:"csr" example:"-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----\n"`
	RsaPrivateKey string                  `json:"rsa_private_key" example:"-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----\n"`
	PrivateKey    string                  `json:"private_key" example:"-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----\n"`
	PublicKey     string                  `json:"public_key" example:"-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----\n"`
	CACertificate string                  `json:"ca_certificate" example:"-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----\n"`
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	csr           *x509.CertificateRequest
	certificate   *x509.Certificate
	caCertificate *x509.Certificate
}
```

**Add `certType` field:**
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

**Part 2 — Fix `GoCRL` return type (lines 109-112).**

**Current:**
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

**Part 3 — Add `Type()` method.** Insert after `GoCACertificate` method (after line ~200):
```go
// Type returns the certificate type string (e.g. "server", "client").
// Returns "" for certificates created before the Type field existed.
func (c *Certificate) Type() string {
	return c.certType
}
```

**Part 4 — Remove `crypto/x509/pkix` import** (no longer needed in goca.go).

**Current imports:**
```go
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"

	"software.sslmate.com/src/go-pkcs12"
)
```

**Replace with:**
```go
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/pkg/errors"
	"software.sslmate.com/src/go-pkcs12"
)
```

**Verify:**
```bash
cd /projects/goca && gofmt -w goca.go && go build ./...
```
**Expected:** errors for `SignCSR` (calls `signCSR` with old signature) and `GeneratePkcs12` (uses deprecated `pkcs12.Encode`).

---

### Task E2: Update `SignCSR` overloads

**File:** `/projects/goca/goca.go`

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

### Task E3: Replace `GeneratePkcs12` with `GeneratePKCS12`

**File:** `/projects/goca/goca.go`

**Why:** `pkcs12.Encode` uses RC2-40 + MD5 (broken). `pkcs12.Modern2023` uses PBES2/AES-256/HMAC-SHA-256.

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

**Edge cases handled:**
- `certificate` is nil → error
- Missing private key or certificate → error
- Empty passphrase → error (required for encryption)

**Verify:**
```bash
cd /projects/goca && gofmt -w . && go build ./... && go vet ./...
```
**Expected:** NO `SA1019` warnings. Full project compiles.

---

### Task E4: Create `aliases.go`

**File:** `/projects/goca/aliases.go` (NEW)

**Why:** Re-exports `CertType`, its constants, and `ParseCertType` from `cert` package so users of the root `goca` package don't need to import `cert` directly.

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
cd /projects/goca && gofmt -w aliases.go && go build ./... && go vet ./...
```

---

## Phase F — Tests

### Task F1: Create `key/key_test.go`

**File:** `/projects/goca/key/key_test.go` (NEW)

```go
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
	pemBytes, err := ConvertRsaPrivateKeyFromDerToPem(kd.Key)
	require.NoError(t, err)
	assert.Contains(t, string(pemBytes), "RSA PRIVATE KEY")

	// Round-trip via LoadPrivateKeyFromPem (which accepts PKCS#1).
	loaded, err := LoadPrivateKeyFromPem(pemBytes)
	require.NoError(t, err)
	assert.True(t, kd.Key.Equal(loaded))
}
```

**Verify:**
```bash
cd /projects/goca && gofmt -w key/key_test.go && go test ./key/...
```

---

### Task F2: Create `cert/cert_test.go`

**File:** `/projects/goca/cert/cert_test.go` (NEW)

```go
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
```

**Verify:**
```bash
cd /projects/goca && gofmt -w cert/cert_test.go && go test ./cert/...
```

---

### Task F3: Create `cert/certtype_test.go`

**File:** `/projects/goca/cert/certtype_test.go` (NEW)

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

### Task F4: Rewrite `goca_test.go`

**File:** `/projects/goca/goca_test.go` — REPLACE ENTIRE FILE

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
	assert.True(t, strings.HasPrefix(string(pfx), "\x30\x82"))
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

**Verify:**
```bash
cd /projects/goca && gofmt -w goca_test.go && go test ./...
```
**Expected:** All tests pass.

---

### Task F5: Rewrite `example_test.go`

**File:** `/projects/goca/example_test.go` — REPLACE ENTIRE FILE

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

**Verify:**
```bash
cd /projects/goca && gofmt -w example_test.go && go test ./...
```
**Expected:** `Example_minimal` passes (including `// Output:` check).

---

## Phase G — Infrastructure

### Task G1: Rewrite `Makefile`

**File:** `/projects/goca/Makefile` — REPLACE ENTIRE FILE

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

### Task G2: Remove Docker files

**Delete these files:**
```bash
rm -f /projects/goca/Dockerfile
rm -f /projects/goca/DOCKER_README.md
```

**Verify:**
```bash
ls /projects/goca/Dockerfile /projects/goca/DOCKER_README.md 2>&1
# Expected: "No such file or directory" for both
```

---

### Task G3: Replace GitHub workflows

**Step 1 — Delete Docker workflows:**
```bash
rm -f /projects/goca/.github/workflows/goca-rest-api-docker-dev.yml
rm -f /projects/goca/.github/workflows/goca-rest-api-docker-release.yml
```

**Step 2 — Replace `/projects/goca/.github/workflows/goca-tests.yml`:**

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

---

### Task G4: Rewrite `README.md`

**File:** `/projects/goca/README.md` — REPLACE ENTIRE FILE

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

---

### Task G5: Fix spelling and stale comments

**File:** `/projects/goca/ca.go`

Find and replace exactly these strings:
- Line with `Intermendiate Certificate Authority` → `Intermediate Certificate Authority`
- Line with `Key Bit Size (defaul: 2048)` → `Key Bit Size (default: 2048)`
- Line with `Minimum 1 day, maximum 825 days` → `Minimum 1 day, maximum 3650 days`
- `// It add it on  rovokated list` → `// It adds the certificate to the revocation list.`
- `// loadCA permti to load existing CA` → `// loadCA loads an existing CA`
- `// create permit to create new CA` → `// create creates a new CA or intermediate CA`

**File:** `/projects/goca/goca.go`
- `// New creat new Certificate Authority` → `// New creates a new Root Certificate Authority`

**File:** `/projects/goca/cert/cert.go`
- `permit to convert CLR from DER format to PEM format` → `converts a CRL from DER format to PEM format`

After edits:
```bash
cd /projects/goca && gofmt -w . && go build ./... && go test ./...
```

---

## Phase H — Final Verification

Run each command from `/projects/goca`. All must succeed.

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
**Expected:** no output. NO `SA1019` warnings.

### H4: Lint
```bash
golangci-lint run ./...
```
**Expected:** no `SA1019` warnings, no errors.

### H5: Tests with race detector
```bash
go test -race -coverprofile=coverage.out -covermode=atomic -v ./...
```
**Expected:** all tests pass; coverage significantly improved.

### H6: Coverage report
```bash
go tool cover -func=coverage.out | tail -1
```
**Expected:** total coverage > 60%.

### H7: Smoke test
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
rm -f /tmp/goca_smoke_test.go
```
**Expected:** six lines with each type's EKU/KU, then `PKCS#12 bytes: NNN`, then `SMOKE OK`. Exit code 0.

---

## Dependency Graph

```
A1 (gofmt) ──┐
             ├─► A2 (cert/certtype.go)
             │
B1..B4 (key) ─┤
             │
C1..C10 (cert)─┤  (C7 uses certtype.go already in package cert)
             │
D1..D8 (ca)  ─┤  (D1, D2 independent; D3 before D4/D5/D6/D8;
             │   D6 before D7; D7 before D8)
             │
E1..E4 (goca)─┤  (E1 before E2; E2 before E3; E4 independent after A2)
             │
F1..F5 (tests)─┤
             │
G1..G5 (infra)─┤
             │
H (final)    ──┘
```

**Minimum safe execution order:**
1. A1 (gofmt all)
2. A2 (cert/certtype.go)
3. B1 → B2 → B3 → B4 (key/key.go)
4. C1 → C2 → C3 → C4 → C5 → C6 → C7 → C8 → C9 → C10 (cert/cert.go)
5. D1 → D2 → D3 → D4 → D5 → D6 → D7 → D8 (ca.go)
6. E1 → E2 → E3 (goca.go)
7. E4 (aliases.go)
8. F1 → F2 → F3 → F4 → F5 (tests)
9. G1 → G2 → G3 → G4 → G5 (infrastructure)
10. H1 → H2 → H3 → H4 → H5 → H6 → H7 (final verification)

---

## Backward Compatibility Summary

| Change | Backward compatible? | Mitigation |
|---|---|---|
| `cert.CASignCSR` gains `certType` param | No (breaking) | `cert.CASignCSRLegacy` keeps old signature |
| `(*CA).GoCRL()` returns `*x509.RevocationList` | No (breaking) | Document as the one breaking change |
| `goca.GeneratePkcs12` deprecated | Yes | Wraps new `goca.GeneratePKCS12` |
| `(*CA).SignCSR` signature unchanged | Yes | Delegates to `SignCSRWithType` with `""` (default) |
| `ErrParentCommonNameNotSpecified` renamed | Yes | Aliased to `ErrParentCANotProvided` |
| `CAData.crl` type changed (unexported field) | Internal only | No public API impact |
| `cert.LoadCRLFromPem` returns `*x509.RevocationList` | Breaking | All internal callers updated |
| `Identity.Type` field added | Yes | Defaults to `""` → `server-client` (historical behavior) |

---

## File Inventory After All Tasks

```
goca/
├── ca.go                       (modified)
├── goca.go                     (modified)
├── goca_test.go                (rewritten)
├── example_test.go             (rewritten)
├── aliases.go                  (NEW)
├── go.mod, go.sum              (unchanged)
├── Makefile                    (rewritten)
├── README.md                   (rewritten)
├── LICENSE                     (unchanged)
├── .gitignore                  (unchanged)
├── .github/workflows/
│   └── goca-tests.yml          (rewritten)
├── cert/
│   ├── cert.go                 (modified)
│   ├── certtype.go             (NEW)
│   ├── cert_test.go            (NEW)
│   └── certtype_test.go        (NEW)
└── key/
    ├── key.go                  (modified)
    └── key_test.go             (NEW)
```

**Removed:** `Dockerfile`, `DOCKER_README.md`,
`.github/workflows/goca-rest-api-docker-dev.yml`,
`.github/workflows/goca-rest-api-docker-release.yml`.
