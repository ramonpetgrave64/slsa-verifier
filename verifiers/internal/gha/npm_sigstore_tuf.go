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
	AttestationKeyUsage = "npm:attestations"
	AttestationKeyID    = "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
	TargetPath          = "registry.npmjs.org/keys.json"
)

// NpmjsKeysTarget describes the structure of the target file.
type NpmjsKeysTarget struct {
	Keys []Key `json:"keys"`
}
type Key struct {
	KeyID     string    `json:"keyId"`
	KeyUsage  string    `json:"keyUsage"`
	PublicKey PublicKey `json:"publicKey"`
}
type PublicKey struct {
	RawBytes   string   `json:"rawBytes"`
	KeyDetails string   `json:"keyDetails"`
	ValidFor   ValidFor `json:"validFor"`
}
type ValidFor struct {
	Start time.Time `json:"start"`
}

type SigstoreTufClient interface {
	GetTarget(target string) ([]byte, error)
}

// NewSigstoreTufClient Get a Sigstore TUF client, which itself is a wrapper around the official TUF client.
func NewSigstoreTufClient() (*sigstoreTuf.Client, error) {
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
GetNpmjsKeysTarget Fetch and parse the keys.json file in Sigstore's root for npmjs
The inner TUF client will verify this "blob" is signed with correct delegate TUF roles
https://github.com/sigstore/root-signing/blob/5fd11f7ec0a993b0f20c335b33e53cfffb986b2e/repository/repository/targets/registry.npmjs.org/7a8ec9678ad824cdccaa7a6dc0961caf8f8df61bc7274189122c123446248426.keys.json#L4
*/
func GetNpmjsKeysTarget(client SigstoreTufClient, targetPath string) (*NpmjsKeysTarget, error) {
	blob, err := client.GetTarget(targetPath)
	if err != nil {
		return nil, fmt.Errorf("getting target: %w", err)
	}
	var keys NpmjsKeysTarget
	err = json.Unmarshal(blob, &keys)
	if err != nil {
		return nil, fmt.Errorf("parsing target: %w", err)
	}
	return &keys, nil
}

// func GetKeyDataByKeyIdAndUsage(keys *NpmjsKeysTarget, keyID string, keyUsage) (string, error)

/*
GetKeyDataWithNpmjsKeysTarget Given our set of keys, return the target key's material.
We may also want to check the existing ValidFor.Start (and a potential future ValidFor.End).
*/
func GetKeyDataWithNpmjsKeysTarget(keys *NpmjsKeysTarget, keyID, keyUsage string) (string, error) {
	for _, key := range keys.Keys {
		if key.KeyID == keyID && key.KeyUsage == keyUsage {
			return key.PublicKey.RawBytes, nil
		}
	}
	return "", fmt.Errorf("could not find key with 'keyUsage':%s", keyUsage)
}

/*
GetKeyDataFromSigstoreTuf given a keyid and keyusage, retriive the keyfile from sigstore's TUF root,
parse the file and return the soecific key material.
See documentation for GetNpmjsKeysTarget

example params:

	keyID: "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
	keyUsage: "npm:attestations"
*/
func GetKeyDataFromSigstoreTuf(keyID, keyUsage string) (string, error) {
	client, err := NewSigstoreTufClient()
	if err != nil {
		return "", err
	}
	keys, err := GetNpmjsKeysTarget(client, TargetPath)
	if err != nil {
		return "", err
	}
	KeyData, err := GetKeyDataWithNpmjsKeysTarget(keys, keyID, keyUsage)
	if err != nil {
		return "", err
	}
	return KeyData, nil
}
