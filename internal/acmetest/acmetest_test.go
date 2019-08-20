package acmetest

import (
	"testing"
)

func TestSplitHostname(t *testing.T) {
	tests := []struct {
		Name              string
		Hostname          string
		ExpectedSubdomain string
		ExpectedDomain    string
		ShouldError       bool
	}{
		{"Just domain", "example.org", "", "example.org", false},
		{"Domain plus host", "www.example.org", "www", "example.org", false},
		{"Domain plus subdomain plus host", "www.subdomain.example.org", "www.subdomain", "example.org", false},
		{"Wildcard subdomain", "*.subdomain.example.org", "*.subdomain", "example.org", false},
		{"Just TLD", "com", "", "", true},
		{"Just TLD with leading .", ".com", "", "", true},
		{"Buncha leading dots", "..example.org", "", "example.org", false},
	}

	for _, test := range tests {
		s, d, err := splitHostname(test.Hostname)
		if test.ShouldError != (err != nil) {
			if test.ShouldError {
				t.Errorf("test %q should have error'd, but didn't.", test.Name)
			} else {
				t.Errorf("test %q should not have error'd, but it did: %v", test.Name, err)
			}
		}

		if test.ExpectedSubdomain != s {
			t.Errorf("failed %q: expected subdomain was %q, got %q", test.Name, test.ExpectedSubdomain, s)
		}

		if test.ExpectedDomain != d {
			t.Errorf("failed %q: expected domain %q, got %q", test.Name, test.ExpectedDomain, d)
		}
	}
}
