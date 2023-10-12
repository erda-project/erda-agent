#!/bin/bash

export NAMESPACE="k8s-ebpf"
export INFLUX_ADDR=""
export INFLUX_ORG=""
export INFLUX_BUCKET=""
export INFLUX_TOKEN=""

# install ebpf agent
function __install_agent {
    echo "install agent..."
    cat agent/role.yaml | envsubst | kubectl apply -f -
    cat agent/daemonset.yaml | envsubst | kubectl apply -f -
}
# install
__install_agent

echo "install end..."
