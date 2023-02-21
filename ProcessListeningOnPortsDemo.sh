#!/usr/bin/env bash
set -eou pipefail


deployment_value=NA
namespace_value=NA
clustername_value=NA
clusterid_value=NA
format_value=table

process_arg() {
    arg=$1

    key="$(echo "$arg" | cut -d "=" -f 1)"
    value="$(echo "$arg" | cut -d "=" -f 2)"
     
    if [[ "$key" == "deployment" ]]; then
        deployment_value="$value"
    elif [[ "$key" == "namespace" ]]; then
	namespace_value="$value"
    elif [[ "$key" == "clustername" ]]; then
	clustername_value="$value"
    elif [[ "$key" == "clusterid" ]]; then
	clusterid_value="$value"
    elif [[ "$key" == "format" ]]; then
	format_value="$value"
    fi
}

process_args() {
     echo "In process_arguments"
     for arg in "$@"; do
         echo "$arg"
	 process_arg "$arg"
     done
}

process_args $@

port=8443
port=8000
export OPEN_BROWSER=false
#export OPEN_BROWSER=true
logmein localhost:$port &> token_file.txt
token="$(cat token_file.txt | sed 's|.*token=||' | sed 's|&type.*||')"

password="$(cat ./deploy/k8s/central-deploy/password)"
curl -sSkf -u "admin:$password" -o /dev/null -w '%{redirect_url}' "https://localhost:$port/sso/providers/basic/4df1b98c-24ed-4073-a9ad-356aec6bb62d/challenge?micro_ts=0"

deployment_option=$1
deployment_value="$(echo "$deployment_option" | cut -d "=" -f 2)"

namespace_option=$2
namespace_value="$(echo "$namespace_option" | cut -d "=" -f 2)"

clustername_option=$3
clustername_value="$(echo "$clustername_option" | cut -d "=" -f 2)"

clusterid_option=$4
clusterid_value="$(echo "$clusterid_option" | cut -d "=" -f 2)"

format_option=$5
format_value="$(echo "$format_option" | cut -d "=" -f 2)"

if [[ "$deployment_value" == "NA" ]]; then
    json_deployments="$(curl --location --silent --request GET "https://localhost:$port/v1/deployments" -k -H "Authorization: Bearer $token")"

    if [[ "$namespace_value" != "NA" ]]; then
	json_deployments="$(echo "$json_deployments" | jq --arg namespace "$namespace_value" '{deployments: [.deployments[] | select(.namespace == $namespace)]}')"
    fi

    if [[ "$clustername_value" != "NA" ]]; then
	json_deployments="$(echo "$json_deployments" | jq --arg clustername "$clustername_value" '{deployments: [.deployments[] | select(.cluster == $clustername)]}')"
    fi
    
    if [[ "$clusterid_value" != "NA" ]]; then
	json_deployments="$(echo "$json_deployments" | jq --arg clusterid "$clusterid_value" '{deployments: [.deployments[] | select(.clusterId == $clusterid)]}')"
    fi

    ndeployment="$(echo $json_deployments | jq '.deployments | length')"
    deployments=()
    for ((i = 0; i < ndeployment; i = i + 1)); do
        deployments+=("$(echo "$json_deployments" | jq .deployments[$i].id | tr -d '"')")
    done
else
    deployments=($deployment_value)
fi


netstat_lines=""

for deployment in ${deployments[@]}; do
    #deployment="$(echo "$deployments" | jq .deployments[$i].id | tr -d '"')"
    #deployment=0a8cae58-a666-48b5-b339-f7c51ad875fb
    listening_endpoints="$(curl --location --silent --request GET "https://localhost:$port/v1/listening_endpoints/deployment/$deployment" -k --header "Authorization: Bearer $token")" || true
    if [[ "$listening_endpoints" != "" ]]; then
        nlistening_endpoints="$(echo $listening_endpoints | jq '.listeningEndpoints | length')"
	if [[ "$nlistening_endpoints" > 0 ]]; then
	    if [[ "$format_value" == "json" ]]; then
                echo "deployment= $deployment"
                echo $listening_endpoints | jq
                echo
            fi	
	fi

        for ((j = 0; j < nlistening_endpoints; j = j + 1)); do
            l4_proto="$(echo $listening_endpoints | jq .listeningEndpoints[$j].endpoint.protocol | tr -d '"')"
            if [[ "$l4_proto" == L4_PROTOCOL_TCP ]]; then
                proto=tcp
            elif [[ "$l4_proto" == L4_PROTOCOL_UDP ]]; then
                proto=udp
            else
               proto=unkown
            fi
            plop_port="$(echo $listening_endpoints | jq .listeningEndpoints[$j].endpoint.port | tr -d '"')"
            namespace="$(echo $listening_endpoints | jq .listeningEndpoints[$j].namespace | tr -d '"')"
            clusterId="$(echo $listening_endpoints | jq .listeningEndpoints[$j].clusterId | tr -d '"')"
            podId="$(echo $listening_endpoints | jq .listeningEndpoints[$j].podId | tr -d '"')"
            containerName="$(echo $listening_endpoints | jq .listeningEndpoints[$j].containerName | tr -d '"')"
            pid="$(echo $listening_endpoints | jq .listeningEndpoints[$j].signal.pid | tr -d '"')"
            name="$(echo $listening_endpoints | jq .listeningEndpoints[$j].signal.name | tr -d '"')"
	    netstat_line="$name\t$pid\t$plop_port\t$proto\t$namespace\t$clusterId\t$podId\t$containerName\n"
            netstat_lines="${netstat_lines}${netstat_line}"
        done
    fi
done

echo
if [[ "$format_value" == "table" ]]; then
    header="Program name\tPID\tPort\tProto\tNamespace\tClusterId\t\t\t\tpodId\t\t\tcontainerName"
    echo -e $header
    echo -e $netstat_lines
fi
