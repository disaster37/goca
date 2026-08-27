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
		Type:               string(goca.CertTypeServer),
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
