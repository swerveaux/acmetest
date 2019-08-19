package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"

	"../../internal/acmetest"
	"github.com/spf13/pflag"
)

const (
	acmeURL        = "https://acme-v02.api.letsencrypt.org/directory"
	acmeStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeLocalURL   = "https://localhost:14000/dir"
)

func main() {
	// key, err := rsa.GenerateKey(rand.Reader, 2048)
	var contactsArg string
	pflag.StringVar(&contactsArg, "contacts", "somebody@example.org", "Command separated list of email contacts")
	pflag.Parse()

	contacts := strings.Split(contactsArg, ",")
	for i := range contacts {
		contacts[i] = fmt.Sprintf("mailto:%s", strings.TrimSpace(contacts[i]))
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	acmeURL := acmeLocalURL
	if acmeURL == acmeLocalURL {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client, err := acmetest.NewClient(acmeURL, key, contacts)
	if err != nil {
		log.Fatal(err)
	}

	err = client.CertApply([]string{"www.example.org", "example.org"})
	if err != nil {
		log.Fatal(err)
	}
}
