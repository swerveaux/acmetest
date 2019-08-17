package acmetest

import (
	"bytes"
	"crypto/ecdsa"
	"io/ioutil"
	"net/http"
)

// Client acts as an ACME client for LetsEncrypt.   It keeps track
// of the current Nonce, the ecdsa key for signing messages, and
// the keyID.
type Client struct {
	Nonce     string
	KID       string
	Key       *ecdsa.PrivateKey
	Directory Directory
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
	c.Nonce = nonce

	c.newAccount(contactEmails)
	return c, err
}

func (c *Client) makeRequest(claimset interface{}, url string) ([]byte, error) {
	var b []byte
	token, err := c.JWSEncodeJSON(claimset, url)
	if err != nil {
		return b, err
	}
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
	c.KID = res.Header.Get("Location")

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
