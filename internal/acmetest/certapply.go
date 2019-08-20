package acmetest

import (
	"encoding/json"
	"fmt"
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
	NotBefore   time.Time        `json:"notBefore,omitempty"`
	NotAfter    time.Time        `json:"notAfter,omitempty"`
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

	return certRes, err
}

// FetchChallenges requests a URL from the CertApply response to find out what challenges are available to prove domain ownership.
func (c *Client) FetchChallenges(url string) (ChallengeResponse, error) {
	var chRes ChallengeResponse
	res, err := c.makeRequest(nil, url, true)
	fmt.Println(string(res))
	err = json.Unmarshal(res, &chRes)

	return chRes, err
}
