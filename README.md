# Verification of SLSA provenance

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/slsa-framework/slsa-verifier/badge)](https://api.securityscorecards.dev/projects/github.com/slsa-framework/slsa-verifier)
[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/6729/badge)](https://bestpractices.coreinfrastructure.org/projects/6729)
[![Go Report Card](https://goreportcard.com/badge/github.com/slsa-framework/slsa-verifier)](https://goreportcard.com/report/github.com/slsa-framework/slsa-verifier)
[![Slack](https://img.shields.io/static/v1?label=openssf.slack.com&message=%23slsa-tooling&color=4A154B&logo=slack)](https://slack.openssf.org/)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

<img align="right" src="https://slsa.dev/images/logo-mono.svg" width="140" height="140">

<!-- markdown-toc --bullets="-" -i README.md -->

<!-- toc -->

- [Overview](#overview)
  - [What is SLSA?](#what-is-slsa)
  - [What is provenance?](#what-is-provenance)
  - [What is slsa-verifier?](#what-is-slsa-verifier)
- [Installation](#installation)
  - [Compilation from source](#compilation-from-source)
    - [Option 1: Install via go](#option-1-install-via-go)
    - [Option 2: Compile manually](#option-2-compile-manually)
  - [Use the installer Action on GitHub Actions](#use-the-installer-action-on-github-actions)
  - [Download the binary](#download-the-binary)
  - [Use Homebrew on macOS](#use-homebrew-on-macos)
- [Available options](#available-options)
- [Option list](#option-list)
  - [Option details](#option-details)
- [Verification for GitHub builders](#verification-for-github-builders)
  - [Artifacts](#artifacts)
  - [Containers](#containers)
  - [npm packages](#npm-packages)
    - [The verify-npm-package command](#the-verify-npm-package-command)
    - [npm packages built using the SLSA3 Node.js builder](#npm-packages-built-using-the-slsa3-nodejs-builder)
    - [npm packages built using the npm CLI](#npm-packages-built-using-the-npm-cli)
  - [Container-based builds](#container-based-builds)
- [Verification for Google Cloud Build](#verification-for-google-cloud-build)
  - [Artifacts](#artifacts-1)
  - [Containers](#containers-1)
- [Known Issues](#known-issues)
  - [tuf: invalid key](#tuf-invalid-key)
  - [panic: assignment to entry in nil map](#panic-assignment-to-entry-in-nil-map)
- [Technical design](#technical-design)
  - [Blog post](#blog-post)
  - [Specifications](#specifications)
  - [TOCTOU attacks](#toctou-attacks)

<!-- tocstop -->

## Overview

### What is SLSA?

[Supply chain Levels for Software Artifacts](https://slsa.dev), or SLSA (salsa),
is a security framework, a check-list of standards and controls to prevent
tampering, improve integrity, and secure packages and infrastructure in your
projects, businesses or enterprises.

SLSA defines an incrementially adoptable set of levels which are defined in
terms of increasing compliance and assurance. SLSA levels are like a common
language to talk about how secure software, supply chains and their component
parts really are.

### What is provenance?

Provenance is information, or metadata, about how a software artifact was
created. This could include information about what source code, build system,
and build steps were used, as well as who and why the build was initiated.
Provenance can be used to determine the authenticity and trustworthiness of
software artifacts that you use.

As part of the framework, SLSA defines a
[provenance format](https://slsa.dev/provenance/) which can be used hold this
metadata.

### What is slsa-verifier?

slsa-verifier is a tool for verifying
[SLSA provenance](https://slsa.dev/provenance/) that was generated by CI/CD
builders. slsa-verifier verifies the provenance by verifying the cryptographic
signatures on provenance to make sure it was created by the expected builder.
It then verifies that various values such as the builder id, source code
repository, ref (branch or tag) matches the expected values.

It currently supports verifying provenance generated by:

1. [SLSA generator](https://github.com/slsa-framework/slsa-github-generator)
1. [Google Cloud Build (GCB)](https://cloud.google.com/build/docs/securing-builds/view-build-provenance).

## Installation

You have two options to install the verifier.

### Compilation from source

#### Option 1: Install via go

If you want to install the verifier, you can run the following command:

```bash
$ go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.5.1
$ slsa-verifier <options>
```

Tools like [dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates) or [renovate](https://github.com/renovatebot/renovate) use your project's go.mod to identify the version of your Go dependencies.
If you install the verifier binary in CI, we strongly recommend you create a placeholder `go.mod` containing slsa-verifier as a dependency to receive updates and keep the binary up-to-date. Use the following the steps:

1. Create a tooling/tooling_test.go file containing the following:

```go
//go:build tools
// +build tools

package main

import (
	_ "github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier"
)
```

1. Run the following commands in the tooling directory. (It will create a go.sum file.)

```bash
$ go mod init <your-project-name>-tooling
$ go mod tidy
```

1. Commit the tooling folder (containing the 3 files tooling_test.go, go.mod and go.sum) to the repository.
1. To install the verifier in your CI, run the following commands:

```bash
$ cd tooling
$ grep _ tooling_test.go | cut -f2 -d '"' | xargs -n1 -t go install
```

Alternatively, if your project does not rely on additional tools and only uses slsa-verifier, you can instead run the following commands:

```bash
$ cd tooling
$ go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier
```

#### Option 2: Compile manually

```bash
$ git clone git@github.com:slsa-framework/slsa-verifier.git
$ cd slsa-verifier && git checkout v2.5.1
$ go run ./cli/slsa-verifier <options>
```

### Use the installer Action on GitHub Actions

If you need to install the verifier to run in a GitHub workflow, use the installer Action as described in [actions/installer/README.md](./actions/installer/README.md).

### Download the binary

Download the binary from the latest release at [https://github.com/slsa-framework/slsa-verifier/releases/tag/v2.5.1](https://github.com/slsa-framework/slsa-verifier/releases/tag/v2.5.1)

Download the [SHA256SUM.md](https://github.com/slsa-framework/slsa-verifier/blob/main/SHA256SUM.md).

Verify the checksum:

```bash
$ sha256sum -c --strict SHA256SUM.md
  slsa-verifier-linux-amd64: OK
```

### Use Homebrew on macOS

If you are using macOS and Homebrew, then you can install the verifier using this community-maintained [formula](https://formulae.brew.sh/formula/slsa-verifier).

## Available options

We currently support artifact verification (for binary blobs) and container images.

## Option list

Below is a list of options currently supported for binary blobs and container images. Note that signature verification is handled seamlessly without the need for developers to manipulate public keys. See [Available options](#available-options) for details on the options exposed to validate the provenance.

```bash
$ git clone git@github.com:slsa-framework/slsa-verifier.git
$ go run ./cli/slsa-verifier/ verify-artifact --help
Verifies SLSA provenance on artifact blobs given as arguments (assuming same provenance)

Usage:
  slsa-verifier verify-artifact [flags] artifact [artifact..]

Flags:
      --build-workflow-input map[]    [optional] a workflow input provided by a user at trigger time in the format 'key=value'. (Only for 'workflow_dispatch' events on GitHub Actions). (default map[])
      --builder-id string             [optional] the unique builder ID who created the provenance
  -h, --help                          help for verify-artifact
      --print-provenance              [optional] print the verified provenance to stdout
      --provenance-path string        path to a provenance file
      --source-branch string          [optional] expected branch the binary was compiled from
      --source-tag string             [optional] expected tag the binary was compiled from
      --source-uri string             expected source repository that should have produced the binary, e.g. github.com/some/repo
      --source-versioned-tag string   [optional] expected version the binary was compiled from. Uses semantic version to match the tag
```

Multiple artifacts can be passed to `verify-artifact`. As long as they are all covered by the same provenance file, the verification will succeed.

### Option details

The following options are available:

| Option                 | Description                                                                                                                                                                                                                                                                                                                                                                                               | Support                                                                                             |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `source-uri`           | Expects a source, for e.g. `github.com/org/repo`.                                                                                                                                                                                                                                                                                                                                                         | All builders                                                                                        |
| `source-branch`        | Expects a `branch` like `main` or `dev`. Not supported for all GitHub Workflow triggers.                                                                                                                                                                                                                                                                                                                  | [GitHub builders](https://github.com/slsa-framework/slsa-github-generator#generation-of-provenance) |
| `source-tag`           | Expects a `tag` like `v0.0.1`. Verifies exact tag used to create the binary. Supported for new [tag](https://github.com/slsa-framework/example-package/blob/main/.github/workflows/e2e.go.tag.main.config-ldflags-assets-tag.slsa3.yml#L5) and [release](https://github.com/slsa-framework/example-package/blob/main/.github/workflows/e2e.go.release.main.config-ldflags-assets-tag.slsa3.yml) triggers. | [GitHub builders](https://github.com/slsa-framework/slsa-github-generator#generation-of-provenance) |
| `source-versioned-tag` | Like `tag`, but verifies using semantic versioning.                                                                                                                                                                                                                                                                                                                                                       | [GitHub builders](https://github.com/slsa-framework/slsa-github-generator#generation-of-provenance) |
| `build-workflow-input` | Expects key-value pairs like `key=value` to match against [inputs](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onworkflow_dispatchinputs) for GitHub Actions `workflow_dispatch` triggers.                                                                                                                                                                      | [GitHub builders](https://github.com/slsa-framework/slsa-github-generator#generation-of-provenance) |

## Verification for GitHub builders

### Artifacts

To verify an artifact, run the following command:

```bash
$ slsa-verifier verify-artifact slsa-test-linux-amd64 \
  --provenance-path slsa-test-linux-amd64.intoto.jsonl \
  --source-uri github.com/slsa-framework/slsa-test \
  --source-tag v1.0.3
Verified signature against tlog entry index 3189970 at URL: https://rekor.sigstore.dev/api/v1/log/entries/206071d5ca7a2346e4db4dcb19a648c7f13b4957e655f4382b735894059bd199
Verified build using builder https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/tags/v1.2.0 at commit 5bb13ef508b2b8ded49f9264d7712f1316830d10
PASSED: Verified SLSA provenance
```

The verified in-toto statement may be written to stdout with the
`--print-provenance` flag to pipe into policy engines.

Only GitHub URIs are supported with the `--source-uri` flag. A tag should not
be specified, even if the provenance was built at some tag. If you intend to do
source versioning validation, you can use `--source-tag` to validate the
release tag. For commit SHA validation, use `--print-provenance` and inspect
the commit SHA of the config source or materials.

Multiple artifacts built from the same GitHub builder can be verified in the
same command, by passing them in the same command line as arguments:

```bash
$ slsa-verifier verify-artifact \
  --provenance-path /tmp/demo/multiple.intoto.jsonl \
  --source-uri github.com/mihaimaruseac/example \
  /tmp/demo/fib /tmp/demo/hello

Verified signature against tlog entry index 9712459 at URL: https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77a1544828b67bb5a2335f7e0d01c504a32ceb6f3a8814ed12c8f1b222d308bd9e8
Verified build using builder https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.4.0 at commit 11fab87c5ee6f46c6f5e68f6c5378c62ce1ca77c
Verifying artifact /tmp/demo/fib: PASSED

Verified signature against tlog entry index 9712459 at URL: https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77a1544828b67bb5a2335f7e0d01c504a32ceb6f3a8814ed12c8f1b222d308bd9e8
Verified build using builder https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.4.0 at commit 11fab87c5ee6f46c6f5e68f6c5378c62ce1ca77c
Verifying artifact /tmp/demo/hello: PASSED

PASSED: Verified SLSA provenance
```

The only requirement is that the provenance file covers all artifacts passed as arguments in the command line (that is, they are a subset of `subject` field in the provenance file).

### Containers

To verify a container image, you need to pass a container image name that is _immutable_ by providing its digest, in order to avoid [TOCTOU attacks](#toctou-attacks).

#### The verify-image command

```bash
$ slsa-verifier verify-image --help
Verifies SLSA provenance for an image

Usage:
  slsa-verifier verify-image [flags] tarball

Flags:
      --build-workflow-input map[]    [optional] a workflow input provided by a user at trigger time in the format 'key=value'. (Only for 'workflow_dispatch' events on GitHub Actions). (default map[])
      --builder-id string             [optional] the unique builder ID who created the provenance
  -h, --help                          help for verify-npm-package
      --print-provenance              [optional] print the verified provenance to stdout
      --provenance-path string        path to a provenance file
      --provenance-repository  string [optional] provenance repository when stored different from image repository. When set, overrides COSIGN_REPOSITORY environment variable
      --source-branch string          [optional] expected branch the binary was compiled from
      --source-tag string             [optional] expected tag the binary was compiled from
      --source-uri string             expected source repository that should have produced the binary, e.g. github.com/some/repo
      --source-versioned-tag string   [optional] expected version the binary was compiled from. Uses semantic version to match the tag
```

First set the image name:

```shell
IMAGE=ghcr.io/ianlewis/actions-test:v0.0.86
```

Get the digest for your container _without_ pulling it using the [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane.md) command:

```shell
IMAGE="${IMAGE}@"$(crane digest "${IMAGE}")
```

To verify a container image, run the following command. Note that to use `ghcr.io` you need to set the `GH_TOKEN` environment variable as well.

```shell
slsa-verifier verify-image "$IMAGE" \
    --source-uri github.com/ianlewis/actions-test \
    --source-tag v0.0.86
```

You should see that the verification passed in the output.

```
Verified build using builder https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v1.4.0 at commit d9be953dd17e7f20c7a234ada668f9c8c4aaafc3
PASSED: Verified SLSA provenance
```

### npm packages

Verification of npm packages is currently an experimental feature.

#### The verify-npm-package command

```bash
$ slsa-verifier verify-npm-package --help
Verifies SLSA provenance for an npm package tarball [experimental]

Usage:
  slsa-verifier verify-npm-package [flags] tarball

Flags:
      --attestations-path string      path to a file containing the attestations
      --build-workflow-input map[]    [optional] a workflow input provided by a user at trigger time in the format 'key=value'. (Only for 'workflow_dispatch' events on GitHub Actions). (default map[])
      --builder-id string             [optional] the unique builder ID who created the provenance
  -h, --help                          help for verify-npm-package
      --package-name string           the package name
      --package-version string        the package version
      --print-provenance              [optional] print the verified provenance to stdout
      --source-branch string          [optional] expected branch the binary was compiled from
      --source-tag string             [optional] expected tag the binary was compiled from
      --source-uri string             expected source repository that should have produced the binary, e.g. github.com/some/repo
      --source-versioned-tag string   [optional] expected version the binary was compiled from. Uses semantic version to match the tag
```

#### npm packages built using the SLSA3 Node.js builder

This section describes how to verify packages built using the SLSA Build L3
[Node.js builder](https://github.com/slsa-framework/slsa-github-generator/blob/main/internal/builders/nodejs/README.md).

To verify an npm package, first download the package tarball and attestations.

```shell
curl -Sso attestations.json $(npm view @ianlewis/actions-test@0.1.127 --json | jq -r '.dist.attestations.url') && \
curl -Sso actions-test.tgz "$(npm view @ianlewis/actions-test@0.1.127 --json | jq -r '.dist.tarball')"
```

You can then verify the package by running the following command:

```shell
SLSA_VERIFIER_EXPERIMENTAL=1 slsa-verifier verify-npm-package actions-test.tgz \
  --attestations-path attestations.json \
  --builder-id "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_nodejs_slsa3.yml" \
  --package-name "@ianlewis/actions-test" \
  --package-version 0.1.127 \
  --source-uri github.com/ianlewis/actions-test
```

The verified in-toto statement may be written to stdout with the
`--print-provenance` flag to pipe into policy engines.

Only GitHub URIs are supported with the `--source-uri` flag. A tag should not
be specified, even if the provenance was built at some tag. If you intend to do
source versioning validation, you can use `--source-tag` to validate the
release tag and `--package-version` to validate the package version. For commit
SHA validation, use `--print-provenance` and inspect the commit SHA of the
config source or materials.

#### npm packages built using the npm CLI

This section describes how to verify packages built using the npm CLI on GitHub.

To verify an npm package, first download the package tarball and attestations.

```shell
curl -Sso attestations.json $(npm view @ianlewis/actions-test@0.1.132 --json | jq -r '.dist.attestations.url') && \
curl -Sso actions-test.tgz "$(npm view @ianlewis/actions-test@0.1.132 --json | jq -r '.dist.tarball')"
```

You can then verify the package by running the following command:

```shell
SLSA_VERIFIER_EXPERIMENTAL=1 slsa-verifier verify-npm-package actions-test.tgz \
  --attestations-path attestations.json \
  --builder-id "https://github.com/actions/runner/github-hosted" \
  --package-name "@ianlewis/actions-test" \
  --package-version 0.1.132 \
  --source-uri github.com/ianlewis/actions-test
```

If the package was built with self-hosted runners, replace
"https://github.com/actions/runner/github-hosted" with
"https://github.com/actions/runner/self-hosted".

The verified in-toto statement may be written to stdout with the
`--print-provenance` flag to pipe into policy engines.

Only GitHub URIs are supported with the `--source-uri` flag. A tag should not
be specified, even if the provenance was built at some tag. If you intend to do
source versioning validation, you can use `--source-tag` to validate the
release tag and `--package-version` to validate the package version. For commit
SHA validation, use `--print-provenance` and inspect the commit SHA of the
config source or materials.

### Container-based builds

To verify an artifact produced by the [Container-based builder](https://github.com/slsa-framework/slsa-github-generator/blob/main/internal/builders/docker/README.md), you will first need to run the following command to verify the provenance like the section above for general [Artifacts](#artifacts):

```bash
$ slsa-verifier verify-artifact slsa-test-linux-amd64 \
  --provenance-path slsa-test-linux-amd64.sigstore \
  --source-uri github.com/slsa-framework/slsa-test \
  --source-tag v1.0.3
Verified signature against tlog entry index 3189970 at URL: https://rekor.sigstore.dev/api/v1/log/entries/206071d5ca7a2346e4db4dcb19a648c7f13b4957e655f4382b735894059bd199
Verified build using builder https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_container-based_slsa3.yml@refs/tags/v1.7.0 at commit 5bb13ef508b2b8ded49f9264d7712f1316830d10
PASSED: Verified SLSA provenance
```

The input provenance is a `.sigstore` file, which is a [Sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto#L63) that contains the in-toto statement containing the SLSA provenance along with verification material. The verified in-toto statement contained in the bundle may be written to stdout with the `--print-provenance` flag to pipe into policy engines.

To verify the user-specified builder image that was used to produce the artifact, extract the builder image with the following command and validate in a policy engine:

```bash
$ cat verifier-statement.intoto | jq -r '.predicate.buildDefinition.externalParameters.builderImage'
```

The builder image is described using an [in-toto Resource Descriptor](https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md).

In case the builds are reproducible, you may also use the internal [docker CLI tool](https://github.com/slsa-framework/slsa-github-generator/tree/main/internal/builders/docker#the-verify-command) to verify the artifact by rebuilding the artifact with the provided provenance.

## Verification for Google Cloud Build

### Artifacts

This is WIP and currently not supported.

### Containers

To verify a container image, you need to pass a container image name that is _immutable_ by providing its digest, in order to avoid [TOCTOU attacks](#toctou-attacks).

First set the image name:

```shell
IMAGE=laurentsimon/slsa-gcb-v0.3:test
```

Download the provenance:

```shell
gcloud artifacts docker images describe $IMAGE --format json --show-provenance > provenance.json
```

Get the digest for your container _without_ pulling it using the [crane](https://github.com/google/go-containerregistry/blob/main/cmd/crane/doc/crane.md) command:

```shell
IMAGE="${IMAGE}@"$(crane digest "${IMAGE}")
```

Verify the image:

```shell
slsa-verifier verify-image "$IMAGE" \
  --provenance-path provenance.json \
  --source-uri github.com/laurentsimon/gcb-tests \
  --builder-id=https://cloudbuild.googleapis.com/GoogleHostedWorker
```

You should see that the verification passed in the output.

```
PASSED: Verified SLSA provenance
```

The verified in-toto statement may be written to stdout with the
`--print-provenance` flag to pipe into policy engines.

Note that `--source-uri` supports GitHub repository URIs like `github.com/$OWNER/$REPO` when the build was enabled with a Cloud Build [GitHub trigger](https://cloud.google.com/build/docs/automating-builds/github/build-repos-from-github). Otherwise, the build provenance will contain the name of the Cloud Storage bucket used to host the source files, usually of the form `gs://[PROJECT_ID]_cloudbuild/source` (see [Running build](https://cloud.google.com/build/docs/running-builds/submit-build-via-cli-api#running_builds)). We recommend using GitHub triggers in order to preserve the source provenance and valiate that the source came from an expected, version-controlled repository. You _may_ match on the fully-qualified tar like `gs://[PROJECT_ID]_cloudbuild/source/1665165360.279777-955d1904741e4bbeb3461080299e929a.tgz`.

### Verification Summary Attestations (VSA)

We have support for [verifying](https://slsa.dev/spec/v1.1/verification_summary#how-to-verify) VSAs.
Rather than passing in filepaths as arguments, we allow passing in mulitple `--subject-digest` cli options, to
accomodate subjects that are not simple-files.

This support does not work yet with VSAs wrapped in Sigstore bundles, only with simple DSSE envelopes.
With that, we allow the user to pass in the public key.
Note that if the DSSE Envelope `signatures` specifies a `keyid` that is not a unpadded base64 encoded sha256 hash the key, like `sha256:abc123...` (not a well-known identifier, e.g, `my-kms:prod-vsa-key`), then you must supply the `--public-key-id` cli option.


The verify-vsa command

```shell
$ slsa-verifier verify-vsa --help
Verifies SLSA VSAs for the given subject-digests

Usage:
  slsa-verifier verify-vsa [flags] subject-digest [subject-digest...]

Flags:
      --attestations-path string      path to a file containing the attestations
  -h, --help                          help for verify-vsa
      --print-attestation             [optional] print the contents of attestation to stdout
      --public-key-hash-algo string   [optional] the hash algorithm used to compute the digest to be signed, one of SHA256 [default], SHA384, or SHA512
      --public-key-id string          [optional] the ID of the public key, defaults to the SHA256 digest of the base64-encoded public key
      --public-key-path string        path to a public key file
      --resource-uri string           the resource URI to be verified
      --subject-digest stringArray    the digests to be verified. Pass multiple digests by repeating the flag. e.g. <digest type>:<digest value>
      --verified-levels strings       [optional] the levels of verification to be performed, comma-separated. e.g., 'SLSA_BUILD_LEVEL_2,FEDRAMP_LOW'
      --verifier-id string            the unique verifier ID who created the attestations
```

To verify VSAs, invoke like this

```shell
$ slsa-verifier verify-vsa \
--subject-digest gce_image_id:8970095005306000053 \
--attestations-path ./cli/slsa-verifier/testdata/vsa/gce/v1/gke-gce-pre.bcid-vsa.jsonl \
--verifier-id https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1 \
--resource-uri gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre \
--verified-levels "BCID_L1, SLSA_BUILD_LEVEL_2" \
--public-key-path ./cli/slsa-verifier/testdata/vsa/gce/v1/vsa_signing_public_key.pem \
--public-key-id keystore://76574:prod:vsa_signing_public_key \
--public-key-hash-algo SHA256 \
--print-attestation
```

For multiple subhects, use:

```
--subject-digest sha256:abc123
--subject-digest sha256:xyz456
```

## Known Issues

### tuf: invalid key

This will occur only when verifying provenance generated with GitHub Actions.

**Affected versions:** v1.3.0-v1.3.1, v1.2.0-v1.2.1, v1.1.0-v1.1.2, v1.0.0-v1.0.4

`slsa-verifier` will fail with the following error:

```
FAILED: SLSA verification failed: could not find a matching valid signature entry: got unexpected errors unable to initialize client, local cache may be corrupt: tuf: invalid key: unable to fetch Rekor public keys from TUF repository
```

This issue is tracked by [issue #325](https://github.com/slsa-framework/slsa-verifier/issues/325). You _must_ update to the newest patch versions of each minor release to fix this issue.

### panic: assignment to entry in nil map

This will occur only when verifying provenance against workflow inputs.

**Affected versions:** v2.0.0

`slsa-verifier` will fail with the following error:

```
panic: assignment to entry in nil map
```

This is fixed by [PR #379](https://github.com/slsa-framework/slsa-verifier/pull/379). You _must_ update to the newest patch versions of each minor release to fix this issue.

## Technical design

### Blog post

Find our blog post series [here](https://security.googleblog.com/2022/04/improving-software-supply-chain.html).

### Specifications

For a more in-depth technical dive, read the [SPECIFICATIONS.md](https://github.com/slsa-framework/slsa-github-generator/blob/main/SPECIFICATIONS.md).

### TOCTOU attacks

As explained on [Wikipedia](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use), a "time-of-check to time-of-use (TOCTOU) is a class of software bugs caused by a race condition involving the checking of the state of a part of a system and the use of the results of that check".

In the context of provenance verification, imagine you verify a container refered to via a _mutable_ image `image:tag`. The verification succeeds and verifies the corresponding hash is `sha256:abcdef...`. After verification, you pull and run the image using `docker run image:tag`. An attacker could have altered the image between the verification step and the run step. To mitigate this attack, we ask users to always pass an _immutable_ reference to the artifact they verify.
