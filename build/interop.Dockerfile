FROM golang:1.27.3 AS go

FROM debian:forky-slim AS inputs

RUN apt-get update && apt-get install -y --no-install-recommends unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Downloaded by prepare-interop.sh, verified again inside the build.
COPY --from=interop-downloads / /download/
COPY build/interop-inputs.txt /tmp/interop-inputs.txt
RUN awk '!/^#/ && NF {print $1 "  /download/" $3}' /tmp/interop-inputs.txt | sha256sum -c - \
    && mkdir -p /opt/opensaml /opt/inputs/saxon \
    && unzip -q /download/idp.zip -d /opt/inputs \
    && unzip -j /download/idp.zip '*/webapp/WEB-INF/lib/*.jar' -d /opt/opensaml \
    && tar -xzf /download/jetty.tar.gz -C /opt/inputs \
    && unzip -q /download/saxon.zip -d /opt/inputs/saxon \
    && unzip -q /download/dss.zip 'dss-demo-bundle-6.5.1/apache-tomcat-11.0.27/*' -d /tmp/dss \
    && mv /tmp/dss/dss-demo-bundle-6.5.1/apache-tomcat-11.0.27 /official-tomcat \
    && cp -R /download/schemas /download/xmlenc /download/xades /opt/inputs/ \
    && cp /download/saxon20.jar /download/rfc9879.txt /opt/inputs/ \
    && cp /opt/inputs/xmlenc/xmldsig-core-schema.xsd /opt/inputs/xades/xmldsig-core-schema-2008.xsd

RUN mkdir -p /opt/inputs/openam/configurator /opt/inputs/openam/admin /opt/inputs/gsa \
    && cp /download/openam.war /opt/inputs/openam/ \
    && cp /download/OpenAM-NameIDMappingResponseImpl.java /opt/inputs/openam/NameIDMappingResponseImpl.java \
    && unzip -q /download/openam-configurator.zip -d /opt/inputs/openam/configurator \
    && unzip -q /download/openam-admin.zip -d /opt/inputs/openam/admin \
    && cp /download/gsa-adaptor.jar /opt/inputs/gsa/ \
    && unzip -q /download/gsa-source.zip 'library-4.1.4/src/com/google/enterprise/adaptor/examples/AdaptorWithCrawlTimeMetadataTemplate.java' -d /opt/inputs/gsa

FROM debian:forky-slim

COPY --from=go /usr/local/go /usr/local/go
COPY --from=inputs /opt/opensaml /opt/opensaml
COPY --from=inputs /opt/inputs /opt/inputs
COPY --from=inputs /official-tomcat /official-tomcat
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOTOOLCHAIN=local \
    GOPATH=/go \
    OPENSAML_CLASSPATH="/opt/opensaml/*" \
    SHIBBOLETH_DIST=/opt/inputs/shibboleth-identity-provider-5.2.3 \
    JETTY_HOME=/opt/inputs/jetty-home-12.1.14 \
    OPENAM_DIST=/opt/inputs/openam \
    TOMCAT_HOME=/official-tomcat \
    GSA_DIST=/opt/inputs/gsa \
    SAXON_CLASSPATH="/opt/inputs/saxon/saxon-he-12.10.jar:/opt/inputs/saxon/lib/*" \
    SAXON20_CLASSPATH=/opt/inputs/saxon20.jar \
    SERIALIZATION_SCHEMA_DIR=/opt/inputs/schemas \
    JSON_SCHEMA_FILE=/opt/inputs/schemas/json.xsd \
    XMLENC_SCHEMA_DIR=/opt/inputs/xmlenc \
    XADES_SCHEMA_DIR=/opt/inputs/xades \
    RFC9879_FILE=/opt/inputs/rfc9879.txt \
    XMLSEC_REQUIRE_INTEROP=1 \
    XMLSEC_INTEROP_SHARDS=2 \
    XMLSEC_INTEROP_PARALLEL=2

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
        patch \
        xmlsec1 \
        xsltproc \
    && rm -rf /var/lib/apt/lists/*

COPY build/patch-openam.sh build/openam-nameid-order.patch /opt/inputs/openam/
RUN sh /opt/inputs/openam/patch-openam.sh /opt/inputs/openam /opt/inputs/openam/openam-nameid-order.patch

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
ENV GOPROXY=off

CMD ["make", "interop-full"]
