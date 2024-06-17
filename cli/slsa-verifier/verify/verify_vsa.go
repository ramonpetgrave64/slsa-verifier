// Copyright 2022 SLSA Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// VerifyVSACommand
type VerifyVSACommand struct {
	SubjectDigests    *[]string
	AttestationsPath  *string
	VerifierID        *string
	ResourceUri       *string
	VerifiedLevels    *[]string
	PrintAttestations *bool
}

// Exec executes the verifiers.VerifyVSA
func (c *VerifyVSACommand) Exec(ctx context.Context) (*utils.TrustedAttesterID, error) {
	if !options.ExperimentalEnabled() {
		err := errors.New("feature support is only provided in SLSA_VERIFIER_EXPERIMENTAL mode")
		printFailed(err)
		return nil, err
	}
	vsaOpts := &options.VSAOpts{
		ExpectedDigests:        *c.SubjectDigests,
		ExpectedVerifierID:     *c.VerifierID,
		ExpectedResourceURI:    *c.ResourceUri,
		ExpectedVerifiedLevels: *c.VerifiedLevels,
	}
	attestations, err := os.ReadFile(*c.AttestationsPath)
	if err != nil {
		printFailed(err)
		return nil, err
	}
	verifiedProvenance, outProducerID, err := verifiers.VerifyVSA(ctx, attestations, vsaOpts)
	if err != nil {
		printFailed(err)
		return nil, err
	}
	if *c.PrintAttestations {
		fmt.Fprintf(os.Stdout, "%s\n", string(verifiedProvenance))
	}
	// verfiers.VerifyVSA already checks if the producerID matches
	return outProducerID, nil
}

// printFailed prints the error message to stderr
func printFailed(err error) {
	fmt.Fprintf(os.Stderr, "Verifying VSA: FAILED: %v\n\n", err)
}