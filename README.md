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
		Type:         string(goca.CertTypeServer),
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

## Key algorithms and validity control

The `Identity` struct supports RSA (default), ECDSA P-256, and Ed25519 keys
for both CAs and issued certificates:

```go
// ECDSA CA with an Ed25519 leaf.
rootCA, _ := goca.New("acme.com", goca.Identity{
	Organization: "ACME Inc.", OrganizationalUnit: "Security",
	Country: "NL", Locality: "Veldhoven", Province: "Noord-Brabant",
	KeyAlgorithm: string(goca.KeyAlgorithmECDSAP256),
})
cert, _ := rootCA.IssueCertificate("leaf.acme.com", goca.Identity{
	Organization: "ACME Inc.",
	KeyAlgorithm: string(goca.KeyAlgorithmEd25519),
	Type:         "client",
})
```

- `KeyAlgorithm` — `"rsa"` (default), `"ecdsa-p256"`, or `"ed25519"`.
  `KeyBitSize` applies only to RSA (default 2048).
- `ValidDuration` — overrides `Valid` when `> 0`, enabling sub-day validity
  (minimum 1 minute, maximum 3650 days). CA validity is day-granular, so a CA
  with `ValidDuration` is rounded down to whole days (minimum 1).
- `Backdate` — shifts issued certificates' `NotBefore` into the past for
  clock-skew tolerance (never earlier than the CA's own `NotBefore`).

To load a CA persisted as just a certificate and private key (e.g. a
Kubernetes Secret), use `LoadCAFromPEM`, which derives the public key and
synthesizes an empty CRL:

```go
loaded := &goca.CA{}
err := loaded.LoadCAFromPEM(certPemBytes, keyPemBytes)
```

## API

| Function | Purpose |
|---|---|
| `goca.New(commonName, identity)` | Create a Root CA |
| `goca.NewCA(commonName, parentCert, parentKey, identity)` | Create an Intermediate CA |
| `(*CA).LoadCA(privKey, pubKey, cert, crl []byte)` | Load a CA from PEM data |
| `(*CA).LoadCAFromPEM(cert, key []byte)` | Load a CA from cert+key PEM only |
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
