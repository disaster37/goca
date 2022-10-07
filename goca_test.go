package goca

import (

	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFunctionalRootCACreation creates a RootCA
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
	assert.NoError(t, err)
	assert.NotNil(t, rootCompanyCA)
	assert.False(t, rootCompanyCA.IsIntermediate())
	assert.Equal(t, "Certificate Authority is ready.", rootCompanyCA.Status())
	assert.NotEmpty(t, rootCompanyCA.GetCertificate())
	assert.NotEmpty(t, rootCompanyCA.GetPrivateKey())
	assert.NotEmpty(t, rootCompanyCA.GetPublicKey())
	assert.NotEmpty(t, rootCompanyCA.GetCRL())
	
}

// Creates a Intermediate CA
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
	if err != nil {
		t.Fatal(err)
	}

	intermediateCAIdentity := Identity{
		Organization:       "Intermediate CA Company Inc.",
		OrganizationalUnit: "Intermediate Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       true,
	}

	intermediateCA, err := NewCA("go-intermediate.ca", rootCompanyCA.GoCertificate(), rootCompanyCA.GoPrivateKey(), intermediateCAIdentity)
	assert.NoError(t, err)
	assert.NotNil(t, intermediateCA)
	assert.True(t, intermediateCA.IsIntermediate())
	assert.NotEmpty(t, intermediateCA.GetCertificate())
	assert.NotEmpty(t, intermediateCA.GetPrivateKey())
	assert.NotEmpty(t, intermediateCA.GetPublicKey())
	assert.NotEmpty(t, intermediateCA.GetCRL())

}


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
	if err != nil {
		t.Fatal(err)
	}


	intranteIdentity := Identity{
		Organization:       "SFTP Server CA Company Inc.",
		OrganizationalUnit: "Intermediate Certificates Management",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       true,
		DNSNames:           []string{"w3.intranet.go-root.ca"},
	}

	intranetCert, err := rootCA.IssueCertificate("intranet.go-root.ca", intranteIdentity)
	assert.NoError(t, err)
	assert.NotNil(t, intranetCert)
	assert.NotEmpty(t, intranetCert.GetCACertificate())
	assert.NotEmpty(t, intranetCert.GetCertificate())
	assert.NotEmpty(t, intranetCert.GetCSR())
	assert.NotEmpty(t, intranetCert.PrivateKey)
}

/*

func TestFunctionalRootCALoadCertificates(t *testing.T) {

	RootCA, err := Load("go-root.ca")
	if err != nil {
		t.Log(err)
		t.Errorf("Failed to load Root CA")
	}

	intranetCert, err := RootCA.LoadCertificate("intranet.go-root.ca")
	if err != nil {
		fmt.Println(err)
		t.Log(err)
	}

	if intranetCert.GetCACertificate() != "" {
		t.Log("Failed to load intranet")
	}
	intermediateCert, _ := RootCA.LoadCertificate("go-intermediate.ca")

	if RootCA.GetCertificate() != intermediateCert.GetCACertificate() {
		t.Log(RootCA.GetCertificate())
		t.Log(intermediateCert.GetCACertificate())
		t.Error("The CA Certificate is not the same as the Certificate CA Certificate")
	}

}

func TestFunctionalIntermediateCAIssueNewCertificate(t *testing.T) {
	id := Identity{
		Organization:       "An Organization",
		OrganizationalUnit: "An Organizational Unit",
		Country:            "NL",
		Locality:           "Noord-Brabant",
		Province:           "Veldhoven",
		Intermediate:       false,
		DNSNames:           []string{"anorg.go-intermediate.ca"},
	}

	interCA, err := Load("go-intermediate.ca")
	if err != nil {
		t.Errorf("Failed to load intermediate CA")
	}

	idCert, err := interCA.IssueCertificate("anorg.go-intermediate.ca", id)
	if err != nil {
		t.Error("Failed to issue certificate anorg.go-intermediate.ca")
	}

	fmt.Println(interCA.ListCertificates())

	if interCA.GetCertificate() != idCert.GetCACertificate() {
		t.Error("CA certificate mismatch between intermediate CA and issued certificate.")
	}
}

func TestFunctionalRevokeCertificate(t *testing.T) {
	RootCA, _ := Load("go-root.ca")
	intermediateCert, _ := RootCA.LoadCertificate("go-intermediate.ca")

	if RootCA.Data.crl == nil {
		t.Error("CRL is nil")
	}

	err := RootCA.RevokeCertificate("go-intermediate.ca")
	if err != nil {
		t.Error("Failed to revoke certificate")
	}
	t.Log(intermediateCert.certificate.SerialNumber)
	t.Log(RootCA.Data.crl.TBSCertList.RevokedCertificates[0].SerialNumber)
	result := intermediateCert.certificate.SerialNumber.Cmp(RootCA.Data.crl.TBSCertList.RevokedCertificates[0].SerialNumber)
	if result != 0 {
		t.Error("Certificate Serial Number is not in the CRL")
	}

	t.Log("Negative check")
	intranetCert, _ := RootCA.LoadCertificate("intranet.go-root.ca")
	t.Log(intranetCert.certificate.SerialNumber)
	t.Log(RootCA.Data.crl.TBSCertList.RevokedCertificates[0].SerialNumber)
	result = intranetCert.certificate.SerialNumber.Cmp(RootCA.Data.crl.TBSCertList.RevokedCertificates[0].SerialNumber)
	if result == 0 {
		t.Error("Non revoked certificate in list")
	}
	err = RootCA.RevokeCertificate("intranet.go-root.ca")
	if err != nil {
		t.Error("Failed to revoke.")
	}
	t.Log(RootCA.Data.crl.TBSCertList.RevokedCertificates)
	if len(RootCA.Data.crl.TBSCertList.RevokedCertificates) != 2 {
		t.Error("Not appending certificates to revoke list")
	}
	t.Logf("Test appending revoked certificates")

	if RootCA.GetCRL() == "" {
		t.Error("CRL X509 file is empty!")
	}
}
*/