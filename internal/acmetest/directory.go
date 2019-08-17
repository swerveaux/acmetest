package acmetest

import "encoding/json"

// Directory encodes a Acme V2 directory as a struct
type Directory struct {
	KeyChange  string `json:"keyChange"`
	NewAccount string `json:"newAccount"`
	NewNonce   string `json:"newNonce"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
}

// Parse gets a chunk of JSON and unmarshals it into a Directory, or else returns an error
func Parse(input []byte) (Directory, error) {
	var d Directory
	err := json.Unmarshal(input, &d)
	return d, err
}
