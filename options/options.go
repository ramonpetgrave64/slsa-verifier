package options

import (
	"log"

	rekorClient "github.com/sigstore/rekor/pkg/generated/client"
	sigstoreTUF "github.com/sigstore/sigstore-go/pkg/tuf"
)

// ProvenanceOpts are the options for checking provenance information.
type ProvenanceOpts struct {
	// ExpectedBranch is the expected branch (github_ref or github_base_ref) in
	// the invocation parameters.
	ExpectedBranch *string

	// ExpectedTag is the expected tag, github_ref, in the invocation parameters.
	ExpectedTag *string

	// ExpectedVersionedTag is the expected versioned tag.
	ExpectedVersionedTag *string

	// ExpectedDigest is the expected artifact sha included in the provenance.
	ExpectedDigest string

	// ExpectedSourceURI is the expected source URI in the provenance.
	ExpectedSourceURI string

	// ExpectedBuilderID is the expected builder ID that is passed from user and verified
	ExpectedBuilderID string

	// ExpectedWorkflowInputs is a map of key=value inputs.
	ExpectedWorkflowInputs map[string]string

	ExpectedPackageName *string

	ExpectedPackageVersion *string

	// ExpectedProvenanceRepository is the provenance repository that is passed from user and not verified
	ExpectedProvenanceRepository *string
}

// BuildOpts are the options for checking the builder.
type BuilderOpts struct {
	// ExpectedBuilderID is the builderID passed in from the user to be verified
	ExpectedID   *string
	VerifierOpts *VerifierOpts
}

// VerifierOpts are the options for the verifier.
type VerifierOpts struct {
	// Logger is the logger to use for the verifier.
	Logger *log.Logger
	// SigstoreTufClient is the Sigstore TUF client.
	SigstoreTUFClient *sigstoreTUF.Client
	// RekorClient is the Rekor client.
	RekorClient *rekorClient.Rekor
}
