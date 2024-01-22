package gha

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

const testTargetLocalFilePath = "./testdata/registry.npmjs.org_keys.json"

var (
	testTargetKeys = npmjsKeysTarget{
		Keys: []key{
			{
				KeyID:    "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
				KeyUsage: "npm:signatures",
				PublicKey: publicKey{
					RawBytes:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==",
					KeyDetails: "PKIX_ECDSA_P256_SHA_256",
					ValidFor: validFor{
						Start: time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
			{
				KeyID:    "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
				KeyUsage: "npm:attestations",
				PublicKey: publicKey{
					RawBytes:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==",
					KeyDetails: "PKIX_ECDSA_P256_SHA_256",
					ValidFor: validFor{
						Start: time.Date(2022, time.December, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
		},
	}
	targetKey          = testTargetKeys.Keys[1]
	testTargetKeyID    = targetKey.KeyID
	testTargetKeyUsage = targetKey.KeyUsage
	testTargetKeyData  = targetKey.PublicKey.RawBytes
)

// mockSigstoreTufClient a mock implementation of sigstoreTufClient.
type mockSigstoreTufClient struct {
	localPath string
}

// GetTarget mock implementation of GetTarget for the mockSigstoreTufClient.
func (client mockSigstoreTufClient) GetTarget(targetPath string) ([]byte, error) {
	content, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, fmt.Errorf("reading mock file: %w", err)
	}
	return content, nil
}

// TestGetNpmjsKeysTarget ensures we can parse the target file.
func TestGetNpmjsKeysTarget(t *testing.T) {
	tests := []struct {
		name         string
		localPath    string
		expectedKeys *npmjsKeysTarget
		expectedErr  error
	}{
		{
			name:         "parsing local registry.npmjs.org_keys.json",
			localPath:    testTargetLocalFilePath,
			expectedKeys: &testTargetKeys,
		},
		{
			name:        "parsing non-existent registry.npmjs.org_keys.json",
			localPath:   "./testdata/my-fake-path",
			expectedErr: ErrorCouldNotFindTarget,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mockSigstoreTufClient{localPath: tt.localPath}
			actualKeys, err := getNpmjsKeysTarget(mockClient, tt.localPath)
			if keyDataDiff := cmp.Diff(tt.expectedKeys, actualKeys, cmpopts.EquateComparable()); keyDataDiff != "" {
				t.Errorf("expected equal values (-want +got):\n%s", keyDataDiff)
			}
			if errorDiff := cmp.Diff(tt.expectedErr, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("expected equaivalent errors (-want +got):\n%s", errorDiff)
			}
		})
	}
}

// TestGetKeyDataWithNpmjsKeysTarget ensure that we find the "npm:attestations" key material, given keyid.
func TestGetKeyDataWithNpmjsKeysTarget(t *testing.T) {
	tests := []struct {
		name            string
		localPath       string
		keyID           string
		keyUsage        string
		expectedKeyData string
		expectedErr     error
	}{
		{
			name:            "npmjs' first attestation key",
			localPath:       testTargetLocalFilePath,
			keyID:           testTargetKeyID,
			keyUsage:        testTargetKeyUsage,
			expectedKeyData: testTargetKeyData,
		},
		{
			name:            "missing the 'npm:attestations' keyusage",
			localPath:       "./testdata/wrong_keyusage_registry.npmjs.org_keys.json",
			keyID:           testTargetKeyID,
			keyUsage:        testTargetKeyUsage,
			expectedKeyData: "", // should not be returned in this error case
			expectedErr:     ErrorMissingNpmjsKeyIDKeyUsage,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mockSigstoreTufClient{localPath: tt.localPath}
			keys, err := getNpmjsKeysTarget(mockClient, tt.localPath)
			if err != nil {
				t.Fatalf("getNpmjsKeysTarget: %v", err)
			}
			actualKeyData, err := getKeyDataWithNpmjsKeysTarget(keys, tt.keyID, tt.keyUsage)
			if keyDataDiff := cmp.Diff(tt.expectedKeyData, actualKeyData); keyDataDiff != "" {
				t.Errorf("expected equal values (-want +got):\n%s", keyDataDiff)
			}
			if errorDiff := cmp.Diff(tt.expectedErr, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("expected equaivalent errors (-want +got):\n%s", errorDiff)
			}
		})
	}
}
