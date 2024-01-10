package gha

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testTargetLocalFilePath = "./testdata/registry.npmjs.org_keys.json"
	testTargetKeyId         = "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
	testTargetKeyMaterial   = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg=="
)

// mockSigstoreTufClient a mock implementation of SigstoreTufClient
type mockSigstoreTufClient struct {
	SigstoreTufClient
	localPath string
}

// GetTarget mock implementation of GetTarget for the mockSigstoreTufClient
func (client mockSigstoreTufClient) GetTarget(targetPath string) ([]byte, error) {
	content, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, fmt.Errorf("reading mock file: %w", err)
	}
	return content, nil
}

// TestGetTarget ensures we can parse the target file
func TestGetNpmjsKeysTarget(t *testing.T) {
	t.Run("parsing local registry.npmjs.org_keys.json", func(t *testing.T) {
		content, err := os.ReadFile(testTargetLocalFilePath)
		assert.NoErrorf(t, err, "reading local file: %s", err)
		var expectedKeys NpmjsKeysTarget
		err = json.Unmarshal(content, &expectedKeys)
		assert.NoErrorf(t, err, "parsing mock file: %s", err)

		mockClient := mockSigstoreTufClient{localPath: testTargetLocalFilePath}
		actualKeys, err := GetNpmjsKeysTarget(mockClient, testTargetLocalFilePath)
		assert.NoError(t, err)
		assert.EqualValues(t, expectedKeys, *actualKeys)
	})

	t.Run("parsing non-existant registry.npmjs.org_keys.json", func(t *testing.T) {
		nonExistantPath := "./testdata/my-fake-path"
		mockClient := mockSigstoreTufClient{localPath: nonExistantPath}
		_, err := GetNpmjsKeysTarget(mockClient, nonExistantPath)
		assert.Error(t, err)
	})
}

// TestGetAttestationKeyMaterialByKeyID ensure that we find the "npm:attestations" key material, given keyid
func TestGetAttestationKeyMaterialByKeyID(t *testing.T) {
	tests := []struct {
		name                string
		localPath           string
		keyID               string
		keyUsage            string
		expectedKeyMaterial string
		expectError         bool
	}{
		{
			name:                "npmjs' first attestation key",
			localPath:           testTargetLocalFilePath,
			keyID:               testTargetKeyId,
			expectedKeyMaterial: testTargetKeyMaterial,
			expectError:         false,
		},
		{
			name:                "missing the 'npm:attestations' keyusage",
			localPath:           "./testdata/wrong_keyusage_registry.npmjs.org_keys.json",
			keyID:               testTargetKeyId,
			expectedKeyMaterial: testTargetKeyMaterial,
			expectError:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := mockSigstoreTufClient{localPath: tt.localPath}
			keys, err := GetNpmjsKeysTarget(mockClient, tt.localPath)
			assert.NoError(t, err)
			actualKeyMaterial, err := GetAttestationKeyMaterialByKeyID(keys, tt.keyID)
			if !tt.expectError {
				assert.NoError(t, err)
				assert.Equalf(t, tt.expectedKeyMaterial, actualKeyMaterial, "key materials do not match")
			} else {
				assert.Errorf(t, err, "expected an error")
				assert.Emptyf(t, actualKeyMaterial, "expetced no value")
			}
		})
	}
}
