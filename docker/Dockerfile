FROM golang:1.22 as builder
LABEL maintainer="dharitri"

# Install git and dependencies
RUN apt-get update && apt-get install -y git

WORKDIR /drt-go-chain-proxy
COPY . .

# Build Proxy
WORKDIR /drt-go-chain-proxy/cmd/proxy

# Remove the git commands from here and use ARG values
ARG VERSION="dev"
ARG COMMIT_SHA="none"
RUN echo "Building version=${VERSION} commit=${COMMIT_SHA}" && \
    go build -ldflags "-X main.appVersion=${VERSION} -X main.commitID=${COMMIT_SHA}"

# ===== SECOND STAGE ======
FROM ubuntu:latest
RUN apt-get update -y && apt-get upgrade -y

# Fix the path to match the builder stage
COPY --from=builder /drt-go-chain-proxy/cmd/proxy/proxy /drt-go-chain-proxy/cmd/proxy/

WORKDIR /drt-go-chain-proxy/cmd/proxy/
EXPOSE 8080
ENTRYPOINT ["./proxy"]