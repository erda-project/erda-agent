#!/bin/bash

export NAMESPACE="kubebpf"
export INFLUX_ADDR="http://influxdb.default.svc.cluster.local:8086"
export INFLUX_ORG="erda"
export INFLUX_BUCKET="ebpf"
export INFLUX_TOKEN=" kWwVy7IfF05yWPdMIlP4k6VPfPV8Uy0rdr583W-0FZ0XYZ93isCyEXc4cKD9xUWVa9bNO2OLp6EakddB-lpbfw=="

# install ebpf agent
function __install_agent {
    echo "install agent..."
    cat agent/role.yaml | envsubst | kubectl apply -f -
    cat agent/daemonset.yaml | envsubst | kubectl apply -f -
}
# install
__install_agent

echo "install end..."
