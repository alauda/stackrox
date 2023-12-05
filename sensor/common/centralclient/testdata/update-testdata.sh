#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# This script will update the testdata for the TLSChallenge tests.
# Usage: ./update-testdata.sh
#
# Prerequisites:
# - roxcurl (can be found in https://github.com/stackrox/workflow)
# - StackRox central instance deployed to `stackrox` namespace, e.g. via ./deploy/k8s/deploy-local.sh
# - jq
# - yq
# - openssl

if ! kubectl -n stackrox get secrets central-tls; then
    echo "Central CA not found. Running StackRox instance with provisioned Central CA cert required."
    exit 1
fi

# Usage: retry <max_retries> <delay_seconds> <function_to_retry>
retry() {
    local max_retries=$1
    local delay=$2
    local func=$3
    local retry_count=0

    while [ $retry_count -lt "$max_retries" ]; do
        ((retry_count++))
        echo "Attempt $retry_count"

        # Execute and check the exit status of the function
        if $func; then
            echo "Function succeeded."
            return 0
        else
            echo "Function failed. Retrying in $delay seconds..."
            sleep "$delay"
        fi
    done

    echo "Max retries reached. Exiting."
    return 1
}

trustInfoResponse=""
exec_tls_challenge() {
    # The token is a random cryptographically generated number. Generation is done in sensor/common/centralclient/client.go:generateChallengeToken
    trustInfoResponse=$(roxcurl "/v1/tls-challenge?challengeToken=h83_PGhSqS8OAvplb8asYMfPHy1JhVVMKcajYyKmrIU=")

    # Check additional-ca is present in response
    additionalCAInResponse=$(go run "$SCRIPT_DIR/unmarshal.go" "$trustInfoResponse")

    CASerialNumberResponse=$(echo "$additionalCAInResponse" | jq -r .additionalCas[0] | base64 --decode | openssl x509 -noout -serial)
    CASerialNumberLocal=$(openssl x509 -noout -serial < "$SCRIPT_DIR/myCA.pem")


    if [[ "$CASerialNumberResponse" != "$CASerialNumberLocal" ]]; then
        echo "Serial Numbers of additional CA did not matched. Waiting until Central loaded new CA cert..."
        echo "Local additional CA: $CASerialNumberLocal"
        echo "Central additional CA: $CASerialNumberResponse"
        return 1
    fi
    echo "Loaded additional CA successfully."
    return 0
}

# Generate an new private key and CA certificate which is used as an additional CA in Central.
openssl genrsa -out "$SCRIPT_DIR"/myCA.key 2048
openssl req -x509 -new -nodes -key "$SCRIPT_DIR"/myCA.key -sha256 -out "$SCRIPT_DIR"/myCA.pem -days 100000 -subj '/CN=Root LoadBalancer Certificate Authority'

# Read and replace additional CA in kubernetes manifest.
additionalCA=$(cat "$SCRIPT_DIR"/myCA.pem)
yq e -i '.stringData.["lb_ca.crt"] = "'"$additionalCA"'"' "$SCRIPT_DIR"/additional-ca.yaml

# Receive new StackRox CA certificate from currently running instance. Save it as testdata to be used in the test case.
kubectl -n stackrox get secret central-tls -o json | jq -r '.data["ca.pem"]' | base64 --decode > "$SCRIPT_DIR"/central-ca.pem

# Apply additional-ca
kubectl -n stackrox apply -f additional-ca.yaml

# retry tls challenge until additional ca was loaded and returned by Central. This is caused by a delay until
# the updated secret is mounted in Central.
retry 10 5 exec_tls_challenge

# read trustInfoResponse from global variable, escape special characters for sed and replace the example variables in the
# corresponding Go file.
trustInfoSerialized=$(echo "$trustInfoResponse" | jq ".trustInfoSerialized" -r) > trust_info_serialied
#sed -i -E 's/trustInfoExample = ".+"/trustInfoExample = "'"$trustInfoSerialized"'"/g' "$SCRIPT_DIR/../client_test.go"

# Update signature example constant.
signature=$(echo "$trustInfoResponse" | jq .signature -r) > signature
#sed -i -E 's/signatureExample = ".+"/signatureExample = "'"$signature"'"/g' "$SCRIPT_DIR/../client_test.go"

echo "Run go unit tests..."
go test ./../
