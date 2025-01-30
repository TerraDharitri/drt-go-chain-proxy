FROM golang:1.21-alpine as builder
LABEL maintainer="TerraDharitri"

WORKDIR /drt-go-chain-proxy
COPY . .

# Install git for version info
RUN apk add --no-cache git

# Proxy
WORKDIR /drt-go-chain-proxy/cmd/proxy
RUN go build -ldflags="-X main.appVersion=$(git describe --tags --long --dirty) -X main.commitID=$(git rev-parse HEAD)"

# ===== SECOND STAGE ======
FROM ubuntu:22.04
RUN apt-get update -y && apt-get upgrade -y

# Fix the COPY path to match your WORKDIR from builder stage
COPY --from=builder /drt-go-chain-proxy/cmd/proxy/proxy /drt-go-chain-proxy/cmd/proxy/

WORKDIR /drt-go-chain-proxy/cmd/proxy/
EXPOSE 8080
ENTRYPOINT ["./proxy"]