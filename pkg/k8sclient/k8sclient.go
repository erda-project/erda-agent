package k8sclient

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
	"os"
)

func GetRestConfig() *rest.Config {
	var config *rest.Config
	incluster := os.Getenv("IN_CLUSTER")
	if incluster == "true" {
		config = InClusterAuth()
	} else {
		config = OutOfClusterAuth()
	}
	return config
}

func InClusterAuth() (config *rest.Config) {
	config, err := rest.InClusterConfig()
	if err != nil {
		klog.Infoln(err.Error())
		os.Exit(3)
	}
	return
}

func OutOfClusterAuth() (config *rest.Config) {

	var err error
	kubeConifg := "/root/.kube/config"
	if os.Getenv("KUBE_CONFIG") != "" {
		kubeConifg = os.Getenv("KUBE_CONFIG")
	}

	// use the current context in kubeconfig
	config, err = clientcmd.BuildConfigFromFlags("", kubeConifg)
	if err != nil {
		klog.Infoln(err.Error())
		os.Exit(3)
	}
	return
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
