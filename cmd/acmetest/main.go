package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/swerveaux/acmetest/internal/acmetest"
)

const (
	acmeURL        = "https://acme-v02.api.letsencrypt.org/directory"
	acmeStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeLocalURL   = "https://localhost:14000/dir"
)

func main() {
	// key, err := rsa.GenerateKey(rand.Reader, 2048)
	var contactsArg string
	var domainsArg string
	pflag.StringVar(&contactsArg, "contacts", "somebody@example.org", "Command separated list of email contacts")
	pflag.StringVar(&domainsArg, "domains", "example.org", "Comma separated list of domains to request certs for.")
	pflag.Parse()

	contacts := strings.Split(contactsArg, ",")
	domains := strings.Split(domainsArg, ",")
	for i := range contacts {
		contacts[i] = fmt.Sprintf("mailto:%s", strings.TrimSpace(contacts[i]))
	}
	for i := range domains {
		domains[i] = strings.TrimSpace(domains[i])
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	acmeURL := acmeStagingURL
	if acmeURL == acmeLocalURL {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client, err := acmetest.NewClient(acmeURL, key, certKey, contacts)
	if err != nil {
		log.Fatal(err)
	}

	certApply, err := client.CertApply(domains)
	if err != nil {
		log.Fatal(err)
	}

	challengeResponse, err := client.FetchChallenges(certApply.Authorizations[0])
	fmt.Println(challengeResponse)
	var challenge acmetest.Challenge
	for _, c := range challengeResponse.Challenges {
		if c.Type == "dns-01" {
			challenge = c
			break
		}
	}
	authHash, err := client.AcmeAuthHash(challenge.Token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(authHash))

	err = client.AddTextRecord(domains[0], authHash)
	if err != nil {
		log.Fatal(err)
	}

	defer func() {
		err = client.RemoveTextRecord(domains[0], authHash)
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-time.After(1 * time.Minute)

	err = client.ChallengeReady(challenge.URL)
	if err != nil {
		log.Printf("Failed posting challenge: %v\n", err)
		return
	}

	err = client.PollForStatus(domains[0])
	if err != nil {
		log.Printf("Bad response when polling: %v\n", err)
	}

}
