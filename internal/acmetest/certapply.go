package acmetest

import (
	"fmt"
	"time"
)

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

// CertApply takes a slice of domain names and tries to appy for certs for them.
func (c *Client) CertApply(domains []string) error {
	identifiers := make([]CertIdentifier, 0, len(domains))
	for _, domain := range domains {
		identifiers = append(identifiers, CertIdentifier{"dns", domain})
	}

	application := CertApply{
		Identifiers: identifiers,
	}

	res, err := c.makeRequest(application, c.Directory.NewOrder)

	fmt.Println(string(res))

	return err
}
