FROM golang:1.27.3 AS go

FROM debian:forky-slim AS archive-tools

RUN apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

FROM archive-tools AS transform-inputs

COPY --from=interop-downloads saxon.zip saxon20.jar /download/
COPY --from=interop-downloads schemas /download/schemas
COPY build/interop-transform-inputs.txt /tmp/interop-inputs.txt
RUN awk '!/^#/ && NF {print $1 "  /download/" $3}' /tmp/interop-inputs.txt | sha256sum -c - \
    && mkdir -p /opt/transform/saxon \
    && unzip -q /download/saxon.zip -d /opt/transform/saxon \
    && cp -R /download/saxon20.jar /download/schemas /opt/transform/

FROM archive-tools AS native-inputs

# Downloaded by prepare-interop.sh, verified again inside the build.
COPY --from=interop-downloads idp.zip jetty.tar.gz dss.zip rfc9879.txt /download/
COPY --from=interop-downloads openam.war openam-configurator.zip openam-admin.zip OpenAM-NameIDMappingResponseImpl.java /download/
COPY --from=interop-downloads gsa-adaptor.jar gsa-source.zip /download/
COPY --from=interop-downloads xmlenc /download/xmlenc
COPY --from=interop-downloads xades /download/xades
COPY build/interop-inputs.txt /tmp/interop-inputs.txt
RUN awk '!/^#/ && NF {print $1 "  /download/" $3}' /tmp/interop-inputs.txt | sha256sum -c - \
    && mkdir -p /opt/opensaml /opt/inputs \
    && unzip -q /download/idp.zip -d /opt/inputs \
    && unzip -j /download/idp.zip '*/webapp/WEB-INF/lib/*.jar' -d /opt/opensaml \
    && tar -xzf /download/jetty.tar.gz -C /opt/inputs \
    && unzip -q /download/dss.zip 'dss-demo-bundle-6.5.1/apache-tomcat-11.0.27/*' -d /tmp/dss \
    && mv /tmp/dss/dss-demo-bundle-6.5.1/apache-tomcat-11.0.27 /official-tomcat \
    && cp -R /download/xmlenc /download/xades /download/rfc9879.txt /opt/inputs/ \
    && cp /opt/inputs/xmlenc/xmldsig-core-schema.xsd /opt/inputs/xades/xmldsig-core-schema-2008.xsd

RUN mkdir -p /opt/inputs/openam/configurator /opt/inputs/openam/admin /opt/inputs/gsa \
    && cp /download/openam.war /opt/inputs/openam/ \
    && cp /download/OpenAM-NameIDMappingResponseImpl.java /opt/inputs/openam/NameIDMappingResponseImpl.java \
    && unzip -q /download/openam-configurator.zip -d /opt/inputs/openam/configurator \
    && unzip -q /download/openam-admin.zip -d /opt/inputs/openam/admin \
    && cp /download/gsa-adaptor.jar /opt/inputs/gsa/ \
    && unzip -q /download/gsa-source.zip 'library-4.1.4/src/com/google/enterprise/adaptor/examples/AdaptorWithCrawlTimeMetadataTemplate.java' -d /opt/inputs/gsa

FROM debian:forky-slim AS interop-base

COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOTOOLCHAIN=local \
    GOPATH=/go \
    SAXON_CLASSPATH="/opt/transform/saxon/saxon-he-12.10.jar:/opt/transform/saxon/lib/*" \
    SAXON20_CLASSPATH=/opt/transform/saxon20.jar \
    SERIALIZATION_SCHEMA_DIR=/opt/transform/schemas \
    JSON_SCHEMA_FILE=/opt/transform/schemas/json.xsd \
    XMLSEC_REQUIRE_INTEROP=1 \
    XMLSEC_INTEROP_SHARDS=2 \
    XMLSEC_INTEROP_PARALLEL=2

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libxml2-utils make openjdk-21-jdk-headless xsltproc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download && go mod verify
ENV GOPROXY=off

FROM interop-base AS transforms

COPY --from=transform-inputs /opt/transform /opt/transform
COPY . .
CMD ["make", "interop-transforms"]

FROM interop-base AS native-runtime

COPY --from=native-inputs /opt/opensaml /opt/opensaml
COPY --from=native-inputs /opt/inputs /opt/inputs
COPY --from=native-inputs /official-tomcat /official-tomcat
ENV \
    OPENSAML_CLASSPATH="/opt/opensaml/*" \
    SHIBBOLETH_DIST=/opt/inputs/shibboleth-identity-provider-5.2.3 \
    JETTY_HOME=/opt/inputs/jetty-home-12.1.14 \
    OPENAM_DIST=/opt/inputs/openam \
    TOMCAT_HOME=/official-tomcat \
    GSA_DIST=/opt/inputs/gsa \
    XMLENC_SCHEMA_DIR=/opt/inputs/xmlenc \
    XADES_SCHEMA_DIR=/opt/inputs/xades \
    RFC9879_FILE=/opt/inputs/rfc9879.txt

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        libssl-dev \
        libxml2-dev \
        libxmlsec1-dev \
        openssl \
        pkg-config \
        patch \
        xmlsec1 \
    && rm -rf /var/lib/apt/lists/*

COPY build/patch-openam.sh build/openam-nameid-order.patch /opt/inputs/openam/
RUN sh /opt/inputs/openam/patch-openam.sh /opt/inputs/openam /opt/inputs/openam/openam-nameid-order.patch

FROM native-runtime AS native

ENV SAXON_CLASSPATH= SAXON20_CLASSPATH= SERIALIZATION_SCHEMA_DIR= JSON_SCHEMA_FILE=
COPY . .
CMD ["make", "interop-native"]

FROM native-runtime AS all

COPY --from=transform-inputs /opt/transform /opt/transform
COPY . .
CMD ["make", "interop-full"]
