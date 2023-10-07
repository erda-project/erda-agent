## README
### 介绍
* 没有使用vmlinux.h,因为它会依赖btf,但是很多低版本的系统并没有开启btf。
* 编译ebfp程序使用容器化的方式，将开发依赖包打进了docker镜像中。

### 编译
``` go
//会同时生成go的二进制制文件以及编译好的.o文件
make
```

### 运行
``` go
//最终采用daemonset的方式运行,使用nodename过滤本节点的endpint来创建ebpf程序。
export nodename="cn-hangzhou.172.16.174.45"
./main
```
