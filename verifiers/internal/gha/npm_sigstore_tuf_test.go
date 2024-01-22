package gha

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const (
	testTargetLocalFilePath = "./testdata/registry.npmjs.org_keys.json"
	testTargetKeyID         = "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
	testTargetKeyUsage      = "npm:attestations"
	testTargetKeyData       = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg=="
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
	t.Run("parsing local registry.npmjs.org_keys.json", func(t *testing.T) {
		content, err := os.ReadFile(testTargetLocalFilePath)
		if err != nil {
			t.Errorf("reading local file: %v", err)
		}
		var expectedKeys npmjsKeysTarget
		if err := json.Unmarshal(content, &expectedKeys); err != nil {
			t.Errorf("parsing mock file: %v", err)
		}
		mockClient := mockSigstoreTufClient{localPath: testTargetLocalFilePath}
		actualKeys, err := getNpmjsKeysTarget(mockClient, testTargetLocalFilePath)
		if err != nil {
			t.Error(err)
		}
		if err != nil {
			t.Error(err)
		}
		if !cmp.Equal(expectedKeys, *actualKeys) {
			t.Errorf("expected equal values: \nexpected: %v \nactual: %v", expectedKeys, *actualKeys)
		}
	})

	t.Run("parsing non-existent registry.npmjs.org_keys.json", func(t *testing.T) {
		nonExistantPath := "./testdata/my-fake-path"
		mockClient := mockSigstoreTufClient{localPath: nonExistantPath}
		_, err := getNpmjsKeysTarget(mockClient, nonExistantPath)
		if err == nil {
			t.Error("expected an error")
		}
	})
}

// TestGetKeyDataWithNpmjsKeysTarget ensure that we find the "npm:attestations" key material, given keyid.
func TestGetKeyDataWithNpmjsKeysTarget(t *testing.T) {
	tests := []struct {
		name            string
		localPath       string
		keyID           string
		keyUsage        string
		expectedKeyData string
		expectError     bool
	}{
		{
			name:            "npmjs' first attestation key",
			localPath:       testTargetLocalFilePath,
			keyID:           testTargetKeyID,
			keyUsage:        testTargetKeyUsage,
			expectedKeyData: testTargetKeyData,
			expectError:     false,
		},
		{
			name:            "missing the 'npm:attestations' keyusage",
			localPath:       "./testdata/wrong_keyusage_registry.npmjs.org_keys.json",
			keyID:           testTargetKeyID,
			keyUsage:        testTargetKeyUsage,
			expectedKeyData: "", // should not be returned in this error case
			expectError:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mockSigstoreTufClient{localPath: tt.localPath}
			keys, err := getNpmjsKeysTarget(mockClient, tt.localPath)
			if err != nil {
				t.Error(err)
			}
			actualKeyData, err := getKeyDataWithNpmjsKeysTarget(keys, tt.keyID, tt.keyUsage)
			if !tt.expectError {
				if err != nil {
					t.Error(err)
				}
				if tt.expectedKeyData != actualKeyData {
					t.Errorf("expected equal values: \nexpected: %v \nactual: %v", tt.expectedKeyData, actualKeyData)
				}
			} else {
				if err == nil {
					t.Error("expected and error")
				}
				if actualKeyData != "" {
					t.Error("expected no returned key data")
				}
			}
		})
	}
}
