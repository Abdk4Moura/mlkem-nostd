#!/usr/bin/env bash
# Fetch the NIST ACVP ML-KEM vector files at a pinned ACVP-Server commit and
# verify every file against vectors/SHA256SUMS.
set -euo pipefail

cd "$(dirname "$0")/.."

ACVP_COMMIT="975de31eb83d87039ec88934fdc47d8c312b892d"
BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/${ACVP_COMMIT}/gen-val/json-files"

# If the files are already present and correct, do not touch the network.
if (cd vectors && sha256sum --check --quiet SHA256SUMS) 2>/dev/null; then
    echo "ACVP vectors already present and verified"
    exit 0
fi

fetch() {
    local dir="$1" file="$2"
    echo "fetching ${dir}/${file}"
    curl --fail --silent --show-error --location \
        "${BASE}/${dir}/${file}" \
        --output "vectors/${dir}/${file}"
}

for dir in ML-KEM-keyGen-FIPS203 ML-KEM-encapDecap-FIPS203; do
    mkdir -p "vectors/${dir}"
    for file in prompt.json expectedResults.json registration.json validation.json; do
        fetch "$dir" "$file"
    done
done
fetch "ML-KEM-keyGen-FIPS203" "internalProjection.json"

(cd vectors && sha256sum --check SHA256SUMS)
echo "ACVP vectors verified against vectors/SHA256SUMS"
