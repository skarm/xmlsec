#!/bin/sh
# Run the pinned, pre-extracted official DSS bundle and its Go checks offline.
# See docs/testing.md for bundle verification, fixtures and the one-command run.
set -eu

dss_version=6.5.1
war_sha256=8cc7fdabcff5509e34c340d88ce648f1cf2a7c7803dd2fcdd541b6f490266a2f

fail() {
    printf '%s\n' "DSS: $*" >&2
    exit 1
}

cleanup() {
    result=$?
    trap - EXIT
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    if [ "$result" -ne 0 ]; then
        tail -n 80 "$log_file" >&2
    fi
    exit "$result"
}

inside() {
    for tool in java keytool jar go bash timeout sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || fail "missing container tool: $tool"
    done
    printf '%s  %s\n' "$war_sha256" /official-tomcat/webapps/ROOT.war | sha256sum -c -
    jar tf /official-tomcat/webapps/ROOT.war | grep -qx "WEB-INF/lib/dss-validation-$dss_version.jar" || fail "DSS $dss_version runtime JAR is absent"
    java_feature=$(java -XshowSettings:properties -version 2>&1 | sed -n 's/^[[:space:]]*java.specification.version = //p')
    case "$java_feature" in ''|*[!0-9]*) fail 'cannot identify the JDK feature version' ;; esac
    [ "$java_feature" -ge 17 ] || fail 'the official bundle requires JDK 17 or later'
    java -version
    go version

    CATALINA_HOME=/official-tomcat
    CATALINA_BASE=/tmp/xmlsec-dss-tomcat
    JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")
    CATALINA_OPTS='-Xms128m -Xmx1024m -Djava.awt.headless=true -Duser.language=en -Duser.country=US'
    export CATALINA_HOME CATALINA_BASE JAVA_HOME CATALINA_OPTS
    mkdir -p "$CATALINA_BASE/conf" "$CATALINA_BASE/logs" "$CATALINA_BASE/temp" "$CATALINA_BASE/work" "$CATALINA_BASE/webapps" "$CATALINA_BASE/lib"
    cp -R "$CATALINA_HOME/conf/." "$CATALINA_BASE/conf/"
    sed -i 's/<Connector port="8080"/<Connector address="127.0.0.1" port="8080"/' "$CATALINA_BASE/conf/server.xml"
    grep -q '<Connector address="127.0.0.1" port="8080"' "$CATALINA_BASE/conf/server.xml" || fail 'the expected loopback connector was not configured'
    ln -s "$CATALINA_HOME/webapps/ROOT.war" "$CATALINA_BASE/webapps/ROOT.war"
    keytool -importcert -noprompt -alias xmlsec-fixture-ca -file "/fixtures/$XMLSEC_DSS_CA_PEM" \
        -keystore "$CATALINA_BASE/lib/xmlsec-dss-roots.p12" -storetype PKCS12 -storepass xmlsec-dss-offline
    # DSS loads the explicit fixture truststore and properties as classpath resources.
    cat > "$CATALINA_BASE/lib/dss-custom.properties" <<'PROPERTIES'
cron.tl.loader.enable=false
cron.lote.loader.enable=false
tl.loader.ades.enabled=false
trusted.source.keystore.type=PKCS12
trusted.source.keystore.filename=xmlsec-dss-roots.p12
trusted.source.keystore.password=xmlsec-dss-offline
dataloader.connection.timeout=100
dataloader.connection.request.timeout=100
dataloader.redirect.enabled=false
bc.asn1.allow_zoneless_utctime=false
PROPERTIES

    log_file="$CATALINA_BASE/logs/console.log"
    sh "$CATALINA_HOME/bin/catalina.sh" run > "$log_file" 2>&1 &
    server_pid=$!
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    attempt=0
    # Use only ready image binaries. Both HTTP and Go run in this network-none
    # namespace; there is no published port or host/remote document upload.
    until timeout 2 bash -s >/dev/null 2>&1 <<'PROBE'
exec 3<>/dev/tcp/127.0.0.1/8080
printf 'GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' >&3
read -r status <&3
case "$status" in 'HTTP/1.1 200'*|'HTTP/1.0 200'*) exit 0 ;; *) exit 1 ;; esac
PROBE
    do
        kill -0 "$server_pid" 2>/dev/null || fail 'Tomcat exited before becoming ready'
        attempt=$((attempt + 1))
        [ "$attempt" -lt 60 ] || fail 'DSS did not become ready within the bounded startup window'
        sleep 1
    done
    export XMLSEC_DSS_URL=http://127.0.0.1:8080/
    export XMLSEC_DSS_FIXTURES="/fixtures/$XMLSEC_DSS_MANIFEST_NAME"
    export XMLSEC_DSS_RUNTIME_JAR="$CATALINA_BASE/webapps/ROOT/WEB-INF/lib/dss-validation-$dss_version.jar"
    export XMLSEC_REQUIRE_P7_PROOFS=1
    # The test checks actual JAR Maven metadata and endpoint version as well as
    # exact fixture trust/source identities; the filenames are not version proof.
    XMLSEC_DSS_REPORT_DIR=${XMLSEC_DSS_REPORT_DIR:-/tmp/xmlsec-dss-reports}
    export XMLSEC_DSS_REPORT_DIR
    mkdir -p "$XMLSEC_DSS_REPORT_DIR"
    go run ./tests/cmd/dev proof capture -out "$XMLSEC_DSS_REPORT_DIR/dss.capture.json" -- \
        -tags=interop ./tests/interop -run '^TestDSS(Historical|Archive)' -timeout=10m -args -suite=portable
}

if [ "${1:-}" = --inside ]; then
    [ "$#" -eq 1 ] || fail 'unexpected internal arguments'
    inside
    exit
fi
case "${1:-}" in ''|--check) ;; *) fail 'usage: sh build/dss.sh [--check]' ;; esac
[ "$#" -le 1 ] || fail 'unexpected arguments'

: "${XMLSEC_DSS_TOMCAT:?path to the extracted official Tomcat directory}"
: "${XMLSEC_DSS_FIXTURE_DIR:?path to the prepared historical fixtures directory}"
: "${XMLSEC_DSS_CA_PEM:?CA PEM filename inside the fixtures directory}"
XMLSEC_DSS_MANIFEST_NAME=${XMLSEC_DSS_MANIFEST_NAME:-manifest.json}
for filename in "$XMLSEC_DSS_CA_PEM" "$XMLSEC_DSS_MANIFEST_NAME"; do
    case "$filename" in ''|.|..|*/*|*\\*) fail 'CA/manifest must be filenames inside the fixture directory' ;; esac
done
workspace=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
tomcat=$(CDPATH='' cd -- "$XMLSEC_DSS_TOMCAT" && pwd -P)
fixtures=$(CDPATH='' cd -- "$XMLSEC_DSS_FIXTURE_DIR" && pwd -P)
[ -f "$tomcat/webapps/ROOT.war" ] && [ -f "$tomcat/bin/catalina.sh" ] || fail 'official Tomcat ROOT.war/launcher is missing'
[ -f "$fixtures/$XMLSEC_DSS_CA_PEM" ] || fail 'fixture CA file is missing'
[ -f "$fixtures/$XMLSEC_DSS_MANIFEST_NAME" ] || fail 'fixture manifest is missing'
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tomcat/webapps/ROOT.war" | awk '{print $1}')
else
    actual=$(shasum -a 256 "$tomcat/webapps/ROOT.war" | awk '{print $1}')
fi
[ "$actual" = "$war_sha256" ] || fail 'official DSS 6.5.1 ROOT.war SHA-256 mismatch'
image=${XMLSEC_DSS_IMAGE:-${INTEROP_DOCKER_IMAGE:-xmlsec-interop:local}}
printf 'DSS %s; image=%s; source=%s; fixtures=%s\n' "$dss_version" "$image" "$workspace" "$fixtures"
if [ "${1:-}" = --check ]; then
    printf '%s\n' 'Input files and pinned WAR checked. Docker/JDK and runtime metadata are checked during the offline run.'
    exit
fi

set -- run --rm --init --network none --memory 3g --cpus 2 \
    --volume "$tomcat:/official-tomcat:ro" --volume "$fixtures:/fixtures:ro" --volume "$workspace:/source:ro" \
    --env GOPROXY=off --env GOSUMDB=off --env GOTOOLCHAIN=local --env GOFLAGS=-mod=readonly \
    --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory --env GIT_CONFIG_VALUE_0=/source \
    --env XMLSEC_DSS_CA_PEM="$XMLSEC_DSS_CA_PEM" --env XMLSEC_DSS_MANIFEST_NAME="$XMLSEC_DSS_MANIFEST_NAME" \
    --workdir /source
if [ -f "$workspace/.git" ]; then
    # A worktree's .git file points outside its source mount. Keep the common
    # repository metadata available read-only for source-bound proof capture.
    git_common=$(git -C "$workspace" rev-parse --path-format=absolute --git-common-dir)
    set -- "$@" --volume "$git_common:$git_common:ro"
fi
if [ -n "${XMLSEC_DSS_GOMODCACHE:-}" ]; then
    modcache=$(CDPATH='' cd -- "$XMLSEC_DSS_GOMODCACHE" && pwd -P)
    set -- "$@" --volume "$modcache:/go/pkg/mod:ro" --env GOMODCACHE=/go/pkg/mod
fi
if [ -n "${XMLSEC_DSS_GOCACHE:-}" ]; then
    mkdir -p "$XMLSEC_DSS_GOCACHE"
    cache=$(CDPATH='' cd -- "$XMLSEC_DSS_GOCACHE" && pwd -P)
    set -- "$@" --volume "$cache:/gocache" --env GOCACHE=/gocache
else
    set -- "$@" --env GOCACHE=/tmp/xmlsec-dss-gocache
fi
if [ -n "${XMLSEC_DSS_REPORT_DIR:-}" ]; then
    mkdir -p "$XMLSEC_DSS_REPORT_DIR"
    reports=$(CDPATH='' cd -- "$XMLSEC_DSS_REPORT_DIR" && pwd -P)
    set -- "$@" --volume "$reports:/reports" --env XMLSEC_DSS_REPORT_DIR=/reports
fi
exec "${DOCKER:-docker}" "$@" "$image" sh /source/build/dss.sh --inside
