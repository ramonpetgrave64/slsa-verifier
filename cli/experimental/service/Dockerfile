FROM golang:1.21@sha256:7d0dcbe5807b1ad7272a598fbf9d7af15b5e2bed4fd6c4c2b5b3684df0b317dd AS base
WORKDIR /src
ENV CGO_ENABLED=0
COPY . ./
RUN go mod vendor
RUN go build -o slsa-verifier -trimpath -ldflags "-s -w -extldflags=-static" -mod=vendor ./cli/experimental/service/main.go

# For testing.
# COPY ./service/service slsa-verifier
# RUN chmod o+x ./slsa-verifier

FROM gcr.io/distroless/base:nonroot@sha256:1a8ece87bd75cde87d0484ef48eb60ea25811baf90967265956ae4fa2098dd9d
COPY --from=base /src/slsa-verifier /
ENTRYPOINT ["/slsa-verifier"]
