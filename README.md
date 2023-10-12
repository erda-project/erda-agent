## 构建
编译agent
``` bash
make
#会生成agent的二进制文件,以及在target目录下生成每一个插件的 ebpf 编译之后 .o文件。
```
镜像agent构建
```bash
make image
```

## 参考或者使用的其他优秀项目
- [ebpf](https://ebpf.io/) a revolutionary Linux kernel technology.
- [cilium](https://github.com/cilium/cilium) eBPF-based Networking, Security, and Observability.
- [influxdb](https://github.com/influxdata/influxdb) Scalable datastore for metrics, events, and real-time analytics.
- [deepflow](https://github.com/deepflowio/deepflow) Application Observability using eBPF.
- [pixie](https://github.com/pixie-io/pixie) Instant Kubernetes-Native Application Observability.
- [grafana](https://github.com/grafana/grafana) The open and composable observability and data visualization platform.
- [telegraf](https://github.com/influxdata/telegraf) The plugin-driven server agent for collecting & reporting metrics.
- [owlk8s](https://github.com/est357/owlk8s) A K8s ClusterIP HTTP monitoring library based on eBPF.
