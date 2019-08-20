package acmetest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/crypto/acme"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
)

// Client acts as an ACME client for LetsEncrypt.   It keeps track
// of the current Nonce, the ecdsa key for signing messages, and
// the keyID.
type Client struct {
	Nonce      string
	KID        string
	Key        *ecdsa.PrivateKey
	Directory  Directory
	AWSSession *session.Session
	R53        *route53.Route53
}

// NewClient takes a directory URL and *ecdsa.PrivateKey and sets up a client.   It will populate
// the Directory from that URL and get a Nonce for the next request.
func NewClient(dirURL string, key *ecdsa.PrivateKey, contactEmails []string) (Client, error) {
	c := Client{Key: key}

	directory, err := queryDirectory(dirURL)
	if err != nil {
		return c, err
	}
	c.Directory = directory

	nonce, err := GetNonce(c.Directory.NewNonce)
	if err != nil {
		return c, err
	}
	fmt.Printf("Fetched nonce: %s\n", nonce)
	c.Nonce = nonce

	c.newAccount(contactEmails)

	c.AWSSession, err = session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	})
	if err != nil {
		return c, err
	}

	c.R53 = route53.New(c.AWSSession)

	return c, nil
}

func (c *Client) makeRequest(claimset interface{}, url string, postAsGet bool) ([]byte, error) {
	var b []byte
	token, err := c.JWSEncodeJSON(claimset, url, postAsGet)
	if err != nil {
		return b, err
	}

	fmt.Printf("Request token sent to %s\n", url)
	fmt.Println(string(token))

	req, err := http.NewRequest("POST", url, bytes.NewReader(token))
	if err != nil {
		return b, err
	}

	req.Header.Set("Content-Type", "application/jose+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return b, err
	}
	defer res.Body.Close()

	b, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return b, err
	}

	c.Nonce = res.Header.Get("Replay-Nonce")
	if c.KID == "" {
		c.KID = res.Header.Get("Location")
	}

	return b, nil
}

func queryDirectory(url string) (Directory, error) {
	var d Directory

	res, err := http.Get(url)
	if err != nil {
		return d, err
	}
	defer res.Body.Close()

	dirJSON, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return d, err
	}

	d, err = Parse(dirJSON)
	return d, err
}

// JWKThumbprint gets a thumbprint of the JWK as defined by RFC7638
func JWKThumbprint(key *ecdsa.PrivateKey) (string, error) {
	return acme.JWKThumbprint(key.Public())
}

func (c *Client) acmeAuthString(token string) (string, error) {
	thumb, err := JWKThumbprint(c.Key)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, base64.RawURLEncoding.EncodeToString([]byte(thumb))), nil
}

// AcmeAuthHash generates the value that should be put into a DNS TXT record for _acme-challenge.{domain}
func (c *Client) AcmeAuthHash(token string) (string, error) {
	authString, err := c.acmeAuthString(token)
	if err != nil {
		return authString, err
	}
	h := sha256.New()
	h.Write([]byte(authString))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
