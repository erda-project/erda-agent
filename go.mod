module github.com/erda-project/ebpf-agent

go 1.19

require (
	github.com/cilium/ebpf v0.11.0
	github.com/erda-project/erda-infra v1.0.8
	github.com/euank/go-kmsg-parser v2.0.0+incompatible
	github.com/influxdata/influxdb-client-go/v2 v2.12.3
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/prometheus/procfs v0.12.0
	k8s.io/api v0.28.1
	k8s.io/apimachinery v0.28.1
	k8s.io/client-go v0.28.1
	k8s.io/cri-api v0.27.1
	k8s.io/klog v1.0.0
	k8s.io/klog/v2 v2.100.1
	k8s.io/kubernetes v1.24.0
)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/deepmap/oapi-codegen v1.8.2 // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/influxdata/line-protocol v0.0.0-20200327222509-2487e7298839 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/recallsong/go-utils v1.1.2-0.20210826100715-fce05eefa294 // indirect
	github.com/recallsong/unmarshal v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/net v0.14.0 // indirect
	golang.org/x/oauth2 v0.10.0 // indirect
	golang.org/x/sys v0.12.0 // indirect
	golang.org/x/term v0.11.0 // indirect
	golang.org/x/text v0.12.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.8.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230711160842-782d3b101e98 // indirect
	google.golang.org/grpc v1.58.2 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.63.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiserver v0.26.2 // indirect
	k8s.io/component-base v0.27.4 // indirect
	k8s.io/kube-openapi v0.0.0-20230717233707-2695361300d9 // indirect
	k8s.io/utils v0.0.0-20230406110748-d93618cff8a2 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

replace (
	k8s.io/api => k8s.io/api v0.24.16
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.24.16
	k8s.io/apimachinery => k8s.io/apimachinery v0.24.16
	k8s.io/apiserver => k8s.io/apiserver v0.24.16
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.24.16
	k8s.io/client-go => k8s.io/client-go v0.24.16
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.24.16
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.24.16
	k8s.io/code-generator => k8s.io/code-generator v0.22.6
	k8s.io/component-base => k8s.io/component-base v0.24.16
	k8s.io/component-helpers => k8s.io/component-helpers v0.24.16
	k8s.io/controller-manager => k8s.io/controller-manager v0.24.16
	k8s.io/cri-api => k8s.io/cri-api v0.24.16
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.24.16
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.24.16
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.24.16
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20220328201542-3ee0da9b0b42
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.24.16
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.24.16
	k8s.io/kubectl => k8s.io/kubectl v0.24.16
	k8s.io/kubelet => k8s.io/kubelet v0.24.16
	k8s.io/kubernetes => k8s.io/kubernetes v1.24.16
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.24.16
	k8s.io/metrics => k8s.io/metrics v0.24.16
	k8s.io/mount-utils => k8s.io/mount-utils v0.24.16
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.24.16
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.24.16
	sigs.k8s.io/controller-runtime => sigs.k8s.io/controller-runtime v0.12.3
)
