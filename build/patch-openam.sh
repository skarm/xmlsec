#!/bin/sh
# Test-runtime correction for OpenAM 16.1.4. Core 3.8.2 extends
# StatusResponseType: its Status must precede NameID/EncryptedID.
# Request processing, account mapping and cryptography remain upstream code.
set -eu
openam_dist=$1
patch_file=$2
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
cp "$openam_dist/NameIDMappingResponseImpl.java" "$work_dir/NameIDMappingResponseImpl.java"
cd "$work_dir"
patch --batch --fuzz=0 < "$patch_file"
jar xf "$openam_dist/openam.war" WEB-INF/lib WEB-INF/classes
javac -cp 'WEB-INF/classes:WEB-INF/lib/*' -d classes NameIDMappingResponseImpl.java
jar uf WEB-INF/lib/openam-federation-library-16.1.4.jar -C classes com/sun/identity/saml2/protocol/impl/NameIDMappingResponseImpl.class
jar uf "$openam_dist/openam.war" WEB-INF/lib/openam-federation-library-16.1.4.jar
printf '%s\n' 'OpenAM 16.1.4: applied test-only SAML Core 3.8.2 serialization-order correction'
