package acmetest

// Most of the functions in this file are directly cribbed
// from github.com/golang/x/crypto/acme/jws.go, mostly for
// the jws token creation and signing for the ACME client.
// That had just about everything we needed but wasn't
// exported and also didn't allow arbitrary headers for the
// "protected" section, which the ACME protocol requires.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// Message is a JWS message for ACME
type Message struct {
	Protected string `json:"protected"` // base64url encoded protected headers
	Payload   string `json:"payload"`   // base64url encoded payload
	Signature string `json:"signature"` // ES256 signature
}

// Protected is the JSON structure for the protected header
type Protected struct {
	Alg   string    `json:"alg"`
	JWK   publicKey `json:"jwk"`
	Nonce string    `json:"nonce"`
	URL   string    `json:"url"`
	Type  string    `json:"typ"`
}

type ecPoint struct {
	R *big.Int
	S *big.Int
}

type publicKey struct {
	Curve string `json:"crv"`
	Kty   string `json:"kty"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

// JWSEncodeJSON signs a claimset using provided key and a nonce.
// The result is serialized in JSON format.
func (c *Client) JWSEncodeJSON(claimset interface{}, url string, postAsGet bool) ([]byte, error) {
	var b []byte
	jwk, err := jwkEncode(c.Key.Public())
	if err != nil {
		return b, err
	}

	alg, sha := jwsHasher(c.Key.Public())
	if alg == "" || !sha.Available() {
		return b, errors.New("Unsupported key")
	}
	var phead string
	if url == c.Directory.NewAccount {
		phead = fmt.Sprintf(`{"alg":%q,"jwk":%s,"nonce":%q,"typ":%q,"url":%q}`, alg, jwk, c.Nonce, "JWT", url)
	} else {
		phead = fmt.Sprintf(`{"alg":%q,"kid":%q,"nonce":%q,"typ":%q,"url":%q}`, alg, c.KID, c.Nonce, "JWT", url)
	}

	phead = base64.RawURLEncoding.EncodeToString([]byte(phead))

	cs, err := json.Marshal(claimset)
	if err != nil {
		return b, err
	}

	fmt.Printf("Encoding %s into base64\n", cs)
	var payload string
	if postAsGet {
		payload = ""
	} else {
		payload = base64.RawURLEncoding.EncodeToString(cs)
	}
	hash := sha.New()
	hash.Write([]byte(phead + "." + payload))

	sig, err := jwsSign(c.Key, sha, hash.Sum(nil))
	if err != nil {
		return nil, err
	}

	enc := struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Sig       string `json:"signature"`
	}{
		Protected: phead,
		Payload:   payload,
		Sig:       base64.RawURLEncoding.EncodeToString(sig),
	}
	return json.Marshal(&enc)
}

func jwkEncode(pub crypto.PublicKey) (string, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		n := pub.N
		e := big.NewInt(int64(pub.E))
		return fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
			base64.RawURLEncoding.EncodeToString(e.Bytes()),
			base64.RawURLEncoding.EncodeToString(n.Bytes()),
		), nil
	case *ecdsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.2.1
		p := pub.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := pub.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := pub.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			p.Name,
			base64.RawURLEncoding.EncodeToString(x),
			base64.RawURLEncoding.EncodeToString(y),
		), nil
	}
	return "", errors.New("Unsupported key type")
}

func jwsSign(key crypto.Signer, hash crypto.Hash, digest []byte) ([]byte, error) {
	if key, ok := key.(*ecdsa.PrivateKey); ok {
		// The key.Sign method of ecdsa returns ASN1-encoded signature.
		// So, we use the package Sign function instead
		// to get R and S values directly and format the result accordingly.
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return nil, err
		}
		rb, sb := r.Bytes(), s.Bytes()
		size := key.Params().BitSize / 8
		if size%8 > 0 {
			size++
		}
		sig := make([]byte, size*2)
		copy(sig[size-len(rb):], rb)
		copy(sig[size*2-len(sb):], sb)

		return sig, nil
	}
	return key.Sign(rand.Reader, digest, hash)
}

func jwsHasher(pub crypto.PublicKey) (string, crypto.Hash) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return "RS256", crypto.SHA256
	case *ecdsa.PublicKey:
		switch pub.Params().Name {
		case "P-256":
			return "ES256", crypto.SHA256
		case "P-384":
			return "ES384", crypto.SHA384
		case "P-521":
			return "ES512", crypto.SHA512
		}
	}
	return "", 0
}
