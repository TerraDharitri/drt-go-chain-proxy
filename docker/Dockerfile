# FROM golang:1.22.11 as builder
# LABEL maintainer="dharitri"

# WORKDIR /drt-go-chain-proxy
# COPY . .

# # Proxy
# WORKDIR /drt-go-chain-proxy/cmd/proxy
# RUN go build -ldflags="-X main.appVersion=$(git describe --tags --long --dirty) -X main.commitID=$(git rev-parse HEAD)"

# # ===== SECOND STAGE ======
# FROM ubuntu:latest
# RUN apt-get update -y && apt-get upgrade -y
# COPY --from=builder /drt-chain-proxy-go/cmd/proxy /drt-go-chain-proxy/cmd/proxy

# WORKDIR /drt-go-chain-proxy/cmd/proxy/
# EXPOSE 8080
# ENTRYPOINT ["./proxy"]


FROM golang:1.22 as builder
LABEL maintainer="terradharitri"

# Install git for version commands
RUN apt-get update && apt-get install -y git

WORKDIR /drt-go-chain-proxy
COPY . .

# Proxy
WORKDIR /drt-go-chain-proxy/cmd/proxy
ARG VERSION
ARG COMMIT_SHA
RUN go build -ldflags="-X main.appVersion=${VERSION} -X main.commitID=${COMMIT_SHA}"

# ===== SECOND STAGE ======
FROM ubuntu:latest
RUN apt-get update -y && apt-get upgrade -y
COPY --from=builder /drt-go-chain-proxy/cmd/proxy/proxy /drt-go-chain-proxy/cmd/proxy/
WORKDIR /drt-go-chain-proxy/cmd/proxy/
EXPOSE 8080
ENTRYPOINT ["./proxy"]