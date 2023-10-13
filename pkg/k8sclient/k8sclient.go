package k8sclient

import (
	"flag"
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"
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
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig",
			filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
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