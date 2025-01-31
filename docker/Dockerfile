FROM golang:1.20.7 as builder
LABEL maintainer="dharitri"

WORKDIR /drt-chain-proxy-go
COPY . .

# Proxy
WORKDIR /drt-chain-proxy-go/cmd/proxy
RUN go build -ldflags="-X main.appVersion=$(git describe --tags --long --dirty) -X main.commitID=$(git rev-parse HEAD)"

# ===== SECOND STAGE ======
FROM ubuntu:22.04
RUN apt-get update -y && apt-get upgrade -y
COPY --from=builder /drt-chain-proxy-go/cmd/proxy /drt-chain-proxy-go/cmd/proxy

WORKDIR /drt-chain-proxy-go/cmd/proxy/
EXPOSE 8080
ENTRYPOINT ["./proxy"]
