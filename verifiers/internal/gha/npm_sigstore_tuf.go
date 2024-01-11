package gha

import (
	"encoding/json"
	"fmt"
	"path"
	"runtime"
	"time"

	sigstoreTuf "github.com/sigstore/sigstore-go/pkg/tuf"
)

const (
	attestationKeyUsage = "npm:attestations"
	attestationKeyID    = "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
	targetPath          = "registry.npmjs.org/keys.json"
)

// npmjsKeysTarget describes the structure of the target file.
type npmjsKeysTarget struct {
	Keys []key `json:"keys"`
}
type key struct {
	KeyID     string    `json:"keyId"`
	KeyUsage  string    `json:"keyUsage"`
	PublicKey publicKey `json:"publicKey"`
}
type publicKey struct {
	RawBytes   string   `json:"rawBytes"`
	KeyDetails string   `json:"keyDetails"`
	ValidFor   validFor `json:"validFor"`
}
type validFor struct {
	Start time.Time `json:"start"`
}

type sigstoreTufClient interface {
	GetTarget(target string) ([]byte, error)
}

// newSigstoreTufClient Get a Sigstore TUF client, which itself is a wrapper around the official TUF client.
func newSigstoreTufClient() (*sigstoreTuf.Client, error) {
	_, filename, _, ok := runtime.Caller(1)
	if !ok {
		return nil, fmt.Errorf("unable to get path")
	}
	opts := sigstoreTuf.DefaultOptions()
	opts.CachePath = path.Join(path.Dir(filename), "tufdata")
	client, err := sigstoreTuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("creating SigstoreTuf client: %w", err)
	}
	return client, nil
}

/*
getNpmjsKeysTarget Fetch and parse the keys.json file in Sigstore's root for npmjs
The inner TUF client will verify this "blob" is signed with correct delegate TUF roles
https://github.com/sigstore/root-signing/blob/5fd11f7ec0a993b0f20c335b33e53cfffb986b2e/repository/repository/targets/registry.npmjs.org/7a8ec9678ad824cdccaa7a6dc0961caf8f8df61bc7274189122c123446248426.keys.json#L4
*/
func getNpmjsKeysTarget(client sigstoreTufClient, targetPath string) (*npmjsKeysTarget, error) {
	blob, err := client.GetTarget(targetPath)
	if err != nil {
		return nil, fmt.Errorf("getting target: %w", err)
	}
	var keys npmjsKeysTarget
	err = json.Unmarshal(blob, &keys)
	if err != nil {
		return nil, fmt.Errorf("parsing target: %w", err)
	}
	return &keys, nil
}

/*
getKeyDataWithNpmjsKeysTarget Given our set of keys, return the target key's material.
We may also want to check the existing ValidFor.Start (and a potential future ValidFor.End).
*/
func getKeyDataWithNpmjsKeysTarget(keys *npmjsKeysTarget, keyID, keyUsage string) (string, error) {
	for _, key := range keys.Keys {
		if key.KeyID == keyID && key.KeyUsage == keyUsage {
			return key.PublicKey.RawBytes, nil
		}
	}
	return "", fmt.Errorf("could not find key with 'keyUsage':%s", keyUsage)
}

/*
getKeyDataFromSigstoreTuf given a keyid and keyusage, retriive the keyfile from sigstore's TUF root,
parse the file and return the specific key material.
See documentation for getNpmjsKeysTarget

example params:

	keyID: "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
	keyUsage: "npm:attestations"
*/
func getKeyDataFromSigstoreTuf(keyID, keyUsage string) (string, error) {
	client, err := newSigstoreTufClient()
	if err != nil {
		return "", err
	}
	keys, err := getNpmjsKeysTarget(client, targetPath)
	if err != nil {
		return "", err
	}
	KeyData, err := getKeyDataWithNpmjsKeysTarget(keys, keyID, keyUsage)
	if err != nil {
		return "", err
	}
	return KeyData, nil
}
