package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"log"
	"net/http"

	"../../internal/acmetest"
)

const (
	acmeURL        = "https://acme-v02.api.letsencrypt.org/directory"
	acmeStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeLocalURL   = "https://localhost:14000/dir"
)

func main() {
	// key, err := rsa.GenerateKey(rand.Reader, 2048)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	acmeURL := acmeLocalURL
	if acmeURL == acmeLocalURL {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client, err := acmetest.NewClient(acmeURL, key, []string{"mailto:someone@example.org"})
	if err != nil {
		log.Fatal(err)
	}

	err = client.CertApply([]string{"www.example.org", "example.org"})
	if err != nil {
		log.Fatal(err)
	}
}
