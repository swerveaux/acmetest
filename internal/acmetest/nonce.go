package acmetest

import "net/http"

// GetNonce takes a URL to fetch a new nonce from the acme server and returns it or an error
func GetNonce(url string) (string, error) {
	var nonce string

	res, err := http.Head(url)
	if err != nil {
		return nonce, err
	}
	defer res.Body.Close()
	nonce = res.Header.Get("Replay-Nonce")
	return nonce, nil
}
