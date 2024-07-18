package gha

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	bundle_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"

	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
)

// Bundle specific errors.
var (
	ErrorMismatchSignature       = errors.New("bundle tlog entry does not match signature")
	ErrorUnexpectedEntryType     = errors.New("unexpected tlog entry type")
	ErrorMissingCertInBundle     = errors.New("missing signing certificate in bundle")
	ErrorUnexpectedBundleContent = errors.New("expected DSSE bundle content")
)

// IsSigstoreBundle checks if the provenance is a Sigstore bundle.
func IsSigstoreBundle(bytes []byte) bool {
	var bundle bundle_v1.Bundle
	if err := protojson.Unmarshal(bytes, &bundle); err != nil {
		return false
	}
	return true
}

// // verifyRekorEntryFromBundle extracts and verifies the Rekor entry from the Sigstore
// // bundle verification material, validating the SignedEntryTimestamp.
// func verifyRekorEntryFromBundle(ctx context.Context, tlogEntry *v1.TransparencyLogEntry,
// 	trustedRoot *TrustedRoot) (
// 	*models.LogEntryAnon, error,
// ) {
// 	canonicalBody := tlogEntry.GetCanonicalizedBody()
// 	logID := hex.EncodeToString(tlogEntry.GetLogId().GetKeyId())
// 	rekorEntry := &models.LogEntryAnon{
// 		Body:           canonicalBody,
// 		IntegratedTime: &tlogEntry.IntegratedTime,
// 		LogIndex:       &tlogEntry.LogIndex,
// 		LogID:          &logID,
// 		Verification: &models.LogEntryAnonVerification{
// 			SignedEntryTimestamp: tlogEntry.GetInclusionPromise().GetSignedEntryTimestamp(),
// 		},
// 	}

// 	// Verify tlog entry.
// 	if _, err := verifyTlogEntry(ctx, *rekorEntry, false,
// 		trustedRoot.RekorPubKeys); err != nil {
// 		return nil, err
// 	}

// 	return rekorEntry, nil
// }

// getEnvelopeFromBundle extracts the DSSE envelope from the Sigstore bundle.
func getEnvelopeFromBundle(bundle *bundle_v1.Bundle) (*dsselib.Envelope, error) {
	dsseEnvelope := bundle.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return nil, ErrorUnexpectedBundleContent
	}
	env := &dsselib.Envelope{
		PayloadType: dsseEnvelope.GetPayloadType(),
		Payload:     base64.StdEncoding.EncodeToString(dsseEnvelope.GetPayload()),
	}
	for _, sig := range dsseEnvelope.GetSignatures() {
		env.Signatures = append(env.Signatures, dsselib.Signature{
			KeyID: sig.GetKeyid(),
			Sig:   base64.StdEncoding.EncodeToString(sig.GetSig()),
		})
	}
	return env, nil
}

func getEnvelopeFromBundleBytes(content []byte) (*dsselib.Envelope, error) {
	var bundle bundle_v1.Bundle
	if err := protojson.Unmarshal(content, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
	}
	env, err := getEnvelopeFromBundle(&bundle)
	if err != nil {
		return nil, err
	}

	return env, nil
}

// getLeafCertFromBundle extracts the signing cert from the Sigstore bundle.
func getLeafCertFromBundle(bundle *bundle_v1.Bundle) (*x509.Certificate, error) {
	certChain := bundle.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	if len(certChain) == 0 {
		return nil, ErrorMissingCertInBundle
	}

	// The first certificate is the leaf cert: see
	// https://github.com/sigstore/protobuf-specs/blob/16541696de137c6281d66d075a4924d9bbd181ff/protos/sigstore_common.proto#L170
	certBytes := certChain[0].GetRawBytes()
	return x509.ParseCertificate(certBytes)
}

// // matchRekorEntryWithEnvelope ensures that the log entry references the given
// // DSSE envelope. It MUST verify that the signatures match to ensure that the
// // tlog timestamp attests to the signature creation time.
// func matchRekorEntryWithEnvelope(tlogEntry *v1.TransparencyLogEntry, env *dsselib.Envelope) error {
// 	kindVersion := tlogEntry.GetKindVersion()
// 	if kindVersion.Kind != "intoto" &&
// 		kindVersion.Version != "0.0.2" {
// 		return fmt.Errorf("%w: expected intoto:0.0.2, got %s:%s", ErrorUnexpectedEntryType,
// 			kindVersion.Kind, kindVersion.Version)
// 	}

// 	canonicalBody := tlogEntry.GetCanonicalizedBody()
// 	var toto models.Intoto
// 	var intotoObj models.IntotoV002Schema
// 	if err := json.Unmarshal(canonicalBody, &toto); err != nil {
// 		return fmt.Errorf("%w: %s", ErrorUnexpectedEntryType, err)
// 	}
// 	specMarshal, err := json.Marshal(toto.Spec)
// 	if err != nil {
// 		return fmt.Errorf("%w: %s", ErrorUnexpectedEntryType, err)
// 	}
// 	if err := json.Unmarshal(specMarshal, &intotoObj); err != nil {
// 		return fmt.Errorf("%w: %s", ErrorUnexpectedEntryType, err)
// 	}

// 	if len(env.Signatures) != len(intotoObj.Content.Envelope.Signatures) {
// 		return fmt.Errorf("expected %d sigs in canonical body, got %d",
// 			len(env.Signatures),
// 			len(intotoObj.Content.Envelope.Signatures))
// 	}

// 	// TODO(#487): verify the certs match.
// 	for _, sig := range env.Signatures {
// 		// The signature in the canonical body is double base64-encoded.
// 		encodedEnvSig := base64.StdEncoding.EncodeToString(
// 			[]byte(sig.Sig))
// 		var matchCanonical bool
// 		for _, canonicalSig := range intotoObj.Content.Envelope.Signatures {
// 			if canonicalSig.Sig.String() == encodedEnvSig {
// 				matchCanonical = true
// 			}
// 		}
// 		if !matchCanonical {
// 			return ErrorMismatchSignature
// 		}
// 	}

// 	return nil
// }

// // VerifyProvenanceBundle verifies the DSSE envelope using the offline Rekor bundle and
// // returns the verified DSSE envelope containing the provenance
// // and the signing certificate given the provenance.
// func VerifyProvenanceBundle(ctx context.Context, bundleBytes []byte,
// 	trustedRoot *TrustedRoot) (
// 	*SignedAttestation, error,
// ) {
// 	proposedSignedAtt, err := verifyBundleAndEntryFromBytes(ctx, bundleBytes, trustedRoot, true)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if err := verifySignedAttestation(proposedSignedAtt, trustedRoot); err != nil {
// 		return nil, err
// 	}

// 	return proposedSignedAtt, nil
// }

// // verifyBundleAndEntry validates the rekor entry inn the bundle
// // and that the entry (cert, signatures) matches the data in the bundle.
// func verifyBundleAndEntry(ctx context.Context, bundle *bundle_v1.Bundle,
// 	trustedRoot *TrustedRoot, requireCert bool,
// ) (*SignedAttestation, error) {
// 	// We only expect one TLOG entry. If this changes in the future, we must iterate
// 	// for a matching one.
// 	if bundle.GetVerificationMaterial() == nil ||
// 		len(bundle.GetVerificationMaterial().GetTlogEntries()) == 0 {
// 		return nil, fmt.Errorf("bundle missing offline tlog verification material %d", len(bundle.GetVerificationMaterial().GetTlogEntries()))
// 	}

// 	// Verify tlog entry.
// 	tlogEntry := bundle.GetVerificationMaterial().GetTlogEntries()[0]
// 	rekorEntry, err := verifyRekorEntryFromBundle(ctx, tlogEntry, trustedRoot)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Extract the PublicKey
// 	publicKey := bundle.GetVerificationMaterial().GetPublicKey()

// 	// Extract DSSE envelope.
// 	env, err := getEnvelopeFromBundle(bundle)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Match tlog entry signature with the envelope.
// 	if err := matchRekorEntryWithEnvelope(tlogEntry, env); err != nil {
// 		return nil, fmt.Errorf("matching bundle entry with content: %w", err)
// 	}

// 	// Get certificate from bundle.
// 	var cert *x509.Certificate
// 	if requireCert {
// 		cert, err = getLeafCertFromBundle(bundle)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}

// 	return &SignedAttestation{
// 		SigningCert: cert,
// 		PublicKey:   publicKey,
// 		Envelope:    env,
// 		RekorEntry:  rekorEntry,
// 	}, nil
// }

// // verifyBundleAndEntryFromBytes validates the rekor entry inn the bundle
// // and that the entry (cert, signatures) matches the data in the bundle.
// func verifyBundleAndEntryFromBytes(ctx context.Context, bundleBytes []byte,
// 	trustedRoot *TrustedRoot, requireCert bool,
// ) (*SignedAttestation, error) {
// 	// Extract the SigningCert, Envelope, and RekorEntry from the bundle.
// 	var bundle bundle_v1.Bundle
// 	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
// 		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
// 	}

// 	return verifyBundleAndEntry(ctx, &bundle,
// 		trustedRoot, requireCert)
// }

// getSignedAttestationFromSigstoreBundle verifies the signatures on the Sigstore bundle and returns the SignedAttestation.
func getSignedAttestationFromSigstoreBundle(provenanceBytes []byte) (*SignedAttestation, error) {
	bundle, err := loadBundleFromBytes(provenanceBytes)
	if err != nil {
		return nil, err
	}

	if err := verifySigstoreBundleSignatures(bundle); err != nil {
		return nil, err
	}

	envelope, err := getEnvelopeFromBundle(bundle.Bundle)
	if err != nil {
		return nil, err
	}

	cert, err := getLeafCertFromBundle(bundle.Bundle)
	if err != nil {
		return nil, err
	}

	publicKey := bundle.GetVerificationMaterial().GetPublicKey()

	signedAttestation := &SignedAttestation{
		Envelope:    envelope,
		SigningCert: cert,
		// RekorEntry: nil, // no need to set this field, if we're not directly using rekor
		PublicKey: publicKey,
	}
	return signedAttestation, nil
}

// verifySigstoreBundle verifies the signatures on the Sigstore bundle.
// It does not check the SAN in the certificate, but subsequent slsa-verifier steps will
// verify the builderID in the certificate.
func verifySigstoreBundleSignatures(bundle *bundle.ProtobufBundle) error {
	sigstoreTrustedRoot, err := utils.GetSigstoreTrustedRoot()
	if err != nil {
		return err
	}

	verifier, err := verify.NewSignedEntityVerifier(
		sigstoreTrustedRoot,

		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithSignedCertificateTimestamps(1),
	)
	if err != nil {
		return err
	}

	policy := verify.NewPolicy(
		verify.WithoutArtifactUnsafe(),
		verify.WithoutIdentitiesUnsafe(), // no SAN check
	)

	_, err = verifier.Verify(bundle, policy)
	if err != nil {
		return err
	}
	return nil
}

// loadBundleFromBytes loads the Sigstore bundle from the provenance bytes.
func loadBundleFromBytes(provenanceBytes []byte) (*bundle.ProtobufBundle, error) {
	var bundle bundle.ProtobufBundle
	bundle.Bundle = new(protobundle.Bundle)
	err := bundle.UnmarshalJSON(provenanceBytes)
	if err != nil {
		return nil, err
	}
	return &bundle, nil
}
