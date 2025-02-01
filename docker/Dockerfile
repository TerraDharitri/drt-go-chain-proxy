# FROM golang:1.22 as builder
# LABEL maintainer="dharitri"

# # Install git and dependencies
# RUN apt-get update && apt-get install -y git

# # Use correct repository name
# WORKDIR /drt-go-chain-proxy
# COPY . .

# # Build Proxy
# WORKDIR /drt-go-chain-proxy/cmd/proxy

# # Use build args with proper quotes and escaping
# ARG VERSION="dev"
# ARG COMMIT_SHA="none"

# RUN go build -ldflags="-X main.appVersion=${VERSION} -X main.commitID=${COMMIT_SHA}"

# # ===== SECOND STAGE ======
# FROM ubuntu:latest
# RUN apt-get update -y && apt-get upgrade -y

# # Fixed path to match first stage
# COPY --from=builder /drt-go-chain-proxy/cmd/proxy/proxy /drt-go-chain-proxy/cmd/proxy/
# WORKDIR /drt-go-chain-proxy/cmd/proxy/

# EXPOSE 8080
# ENTRYPOINT ["./proxy"]

FROM golang:1.22 as builder
LABEL maintainer="dharitri"

# Install git and dependencies
RUN apt-get update && apt-get install -y git

# Use correct repository name
WORKDIR /drt-go-chain-proxy
COPY . .

# Build Proxy
WORKDIR /drt-go-chain-proxy/cmd/proxy

# Build with explicit flags and optimizations
ARG VERSION="dev"
ARG COMMIT_SHA="none"
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
    -X 'main.appVersion=${VERSION}' \
    -X 'main.commitID=${COMMIT_SHA}'" \
    -o proxy

# ===== SECOND STAGE ======
FROM ubuntu:latest as runner

# Install only necessary packages and clean up
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy only the binary
COPY --from=builder /drt-go-chain-proxy/cmd/proxy/proxy /usr/local/bin/proxy

# Use non-root user for security
RUN useradd -r -s /bin/false appuser
USER appuser

WORKDIR /usr/local/bin
EXPOSE 8080

ENTRYPOINT ["proxy"]