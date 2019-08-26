package acmetest

import (
	"bufio"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

// EmptyRequest is an empty struct used for the "POST-as-GET" requests
type EmptyRequest struct {
}

// CertIdentifier lets us marshal the JSON identifiers.
type CertIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// CertApply lets us marshal the JSON cert application
type CertApply struct {
	Identifiers []CertIdentifier `json:"identifiers"`
	// 	NotBefore   time.Time        `json:"notBefore,omitempty"`
	// 	NotAfter    time.Time        `json:"notAfter,omitempty"`
}

// CertResponse lets us unmarshal the response for a cert application
type CertResponse struct {
	Status         string           `json:"status"`
	Expires        time.Time        `json:"expires"`
	NotBefore      time.Time        `json:"notBefore"`
	NotAfter       time.Time        `json:"notAfter"`
	Identifiers    []CertIdentifier `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate"`
}

// Challenge lets us unmarshal challenge data from a JSON response
type Challenge struct {
	Type  string `json:"type"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

// ChallengeResponse lets us unmarshal the response for the challenges for a domain
type ChallengeResponse struct {
	Status     string         `json:"status"`
	Expires    time.Time      `json:"expires"`
	Identifier CertIdentifier `json:"identifier"`
	Challenges []Challenge    `json:"challenges"`
}

// CSRRequest is the payload we send to a finalize
type CSRRequest struct {
	CSR string `json:"csr"`
}

// CertApply takes a slice of domain names and tries to appy for certs for them.
func (c *Client) CertApply(domains []string) (CertResponse, error) {
	identifiers := make([]CertIdentifier, 0, len(domains))
	for _, domain := range domains {
		identifiers = append(identifiers, CertIdentifier{"dns", domain})
	}

	application := CertApply{
		Identifiers: identifiers,
	}

	res, err := c.makeRequest(application, c.Directory.NewOrder, false)

	fmt.Println(string(res))
	var certRes CertResponse
	err = json.Unmarshal(res, &certRes)

	if certRes.Finalize != "" {
		c.Finalize = certRes.Finalize
	}

	return certRes, err
}

// FetchChallenges requests a URL from the CertApply response to find out what challenges are available to prove domain ownership.
func (c *Client) FetchChallenges(url string) (ChallengeResponse, error) {
	var chRes ChallengeResponse
	c.OrderURL = url
	res, err := c.makeRequest(nil, url, true)
	fmt.Println(string(res))
	err = json.Unmarshal(res, &chRes)

	return chRes, err
}

// ChallengeReady sends a POST to letsencrypt to let it know that
// an authorization challenge is ready to validated.
func (c *Client) ChallengeReady(challengeURL string) error {
	_, err := c.makeRequest(EmptyRequest{}, challengeURL, false)
	return err
}

// PollForStatus is a PostAsGet request to the order URL waiting for a non-pending status
func (c *Client) PollForStatus(domain string) error {
	var res []byte
	var err error
	challengeFinished := false
	var certRes CertResponse
	for !challengeFinished {
		<-time.After(5 * time.Second)
		res, err = c.makeRequest(EmptyRequest{}, c.OrderURL, true)
		if err != nil {
			return err
		}
		fmt.Println("While polling, got...")
		fmt.Println(string(res))
		err = json.Unmarshal(res, &certRes)
		if err != nil {
			return err
		}
		if certRes.Status == "valid" || certRes.Status == "invalid" {
			fmt.Printf("Setting challengeFinished to true because status was %q\n", certRes.Status)
			challengeFinished = true
		}
	}

	fmt.Println("Response after exiting loop")
	fmt.Println(string(res))

	if certRes.Status != "valid" {
		return fmt.Errorf("Cert request status %q", certRes.Status)
	}

	csrTemplate := x509.CertificateRequest{
		DNSNames: []string{domain},
		// EmailAddresses: c.ContactEmails,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, c.CertKey)
	if err != nil {
		return err
	}

	res, err = c.makeRequest(CSRRequest{CSR: base64.RawURLEncoding.EncodeToString(csr)}, c.Finalize, false)
	if err != nil {
		return err
	}
	fmt.Println("After sending CSR request to finalize")
	fmt.Println(string(res))
	err = json.Unmarshal(res, &certRes)
	if err != nil {
		return err
	}

	// 	fmt.Println(string(res))

	// challengeFinished = false
	// for !challengeFinished {
	// 	<-time.After(5 * time.Second)
	// 	res, err = c.makeRequest(EmptyRequest{}, c.OrderURL, true)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	fmt.Println("While polling, got...")
	// 	fmt.Println(string(res))
	// 	err = json.Unmarshal(res, &certRes)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	if certRes.Status == "valid" || certRes.Status == "invalid" {
	// 		fmt.Printf("Setting challengeFinished to true because status was %q\n", certRes.Status)
	// 		challengeFinished = true
	// 	}
	// }

	// fmt.Println(string(res))
	// fmt.Printf("Finalize is %q", c.Finalize)

	keyfile, err := os.Create("/tmp/cert.key")
	if err != nil {
		return err
	}
	defer keyfile.Close()
	keywriter := bufio.NewWriter(keyfile)
	pemdata := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.CertKey),
	})
	fmt.Println("Key PEM")
	fmt.Println(string(pemdata))
	_, err = keywriter.Write(pemdata)
	keywriter.Flush()

	certfile, err := os.Create("/tmp/cert.crt")
	if err != nil {
		return err
	}
	defer certfile.Close()

	certwriter := bufio.NewWriter(certfile)
	httpRes, err := http.Get(certRes.Certificate)
	if err != nil {
		fmt.Printf("Failed downloading cert: %v\n", err)
		return err
	}

	defer httpRes.Body.Close()
	cert, err := ioutil.ReadAll(httpRes.Body)
	fmt.Println("Cert PEM")
	fmt.Println(string(cert))
	if err != nil {
		fmt.Printf("Unable to read cert body: %v\n", err)
		return err
	}
	certwriter.Write(cert)
	certwriter.Flush()

	return nil
}
