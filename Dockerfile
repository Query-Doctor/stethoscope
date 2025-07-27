# Use Ubuntu as base image for better eBPF support
FROM ubuntu:24.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV GO_VERSION=1.23.11
ENV BPFTRACE_VERSION=v0.23.5

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    pkg-config \
    libsqlite3-dev \
    linux-headers-generic \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# Set Go environment variables
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV GOCACHE=/go/cache

RUN apt-get update 

# Build and install bpftrace from source
RUN wget https://github.com/bpftrace/bpftrace/releases/download/v0.23.5/bpftrace \
    && chmod +x bpftrace \
    && mv bpftrace /usr/local/bin/bpftrace

# Create app directory
WORKDIR /app

# Copy Go module files
COPY go.mod go.sum ./

# Download Go dependencies
RUN go mod download

# Copy source code
COPY . ./
COPY userland.go ./

# Build the Go application
RUN go generate && go build -o main

# Set the entrypoint
ENTRYPOINT ["./main"]
