package utils

// SigstoreTUFClient is an interface for the Sigstore TUF client.
type SigstoreTUFClient interface {
	// GetTarget gets the target from the TUF root.
	GetTarget(target string) ([]byte, error)
}
