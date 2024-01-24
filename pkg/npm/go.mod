module github.com/slsa-framework/slsa-verifier/v2/pkg/npm

go 1.22

require (
	github.com/google/go-cmp v0.6.0
	github.com/sigstore/sigstore-go v0.0.0-20240108223800-a3df13b8ba29
)

// use the pending PR #41 branch tuf-client-2
replace github.com/sigstore/sigstore-go => github.com/sigstore/sigstore-go v0.0.0-20231222133331-d489b534902f

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-containerregistry v0.16.1 // indirect
	github.com/kr/text v0.1.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20221109233200-85aa52084eaf // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/rdimitrov/go-tuf-metadata v0.0.0-20231211110834-6de72dba550c // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/sigstore/sigstore v1.7.6 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/term v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231120223509-83a465c0220f // indirect
	google.golang.org/grpc v1.59.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
