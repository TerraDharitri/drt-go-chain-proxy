FROM golang:1.22 as builder
LABEL maintainer="dharitri"

# Install git for version commands
RUN apt-get update && apt-get install -y git

WORKDIR /drt-go-chain-proxy
COPY . .

# Proxy
WORKDIR /drt-go-chain-proxy/cmd/proxy

# Using ARG for version information
ARG VERSION
ARG COMMIT_SHA
# Using variables directly in ldflags
RUN go build -ldflags="-X main.appVersion=${VERSION} -X main.commitID=${COMMIT_SHA}"

# ===== SECOND STAGE ======
FROM ubuntu:latest
RUN apt-get update -y && apt-get upgrade -y

# Copy the binary from builder stage
COPY --from=builder /drt-go-chain-proxy/cmd/proxy/proxy /drt-go-chain-proxy/cmd/proxy/

WORKDIR /drt-go-chain-proxy/cmd/proxy/
EXPOSE 8080
ENTRYPOINT ["./proxy"]