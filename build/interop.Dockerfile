FROM golang:1.27.2 AS go

FROM debian:forky-slim

COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOTOOLCHAIN=local \
    GOPATH=/go

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        libssl-dev \
        libxml2-dev \
        libxml2-utils \
        libxmlsec1-dev \
        openjdk-21-jdk-headless \
        openssl \
        pkg-config \
        xmlsec1 \
        xsltproc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
ENV GOPROXY=off

CMD ["make", "interop-full"]
