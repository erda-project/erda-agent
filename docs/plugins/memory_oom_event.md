## Out-Of-Memory 插件
  用于采集集群中的内存使用情况, 监听oom时间产生指标.

### 原理
ebpf-agent通过daemonset的方式部署在集群中, 挂仔主机的rootfs文件, 监听/dev/kmsg文件, 
当container发生oom时, 会从内核中监听到事件, 事件内容大概为:
```text
6,30574067,3816544225424,-;Task in /kubepods.slice/kubepods-pod9eb0e64e_6e1a_43e4_b372_2603a3cc2941.slice/docker-663f6287c450aea2f849b82a30d1409059497b5de62846a286e55971d61e2650.scope killed as a result of limit of /kubepods.slice/kubepods-pod9eb0e64e_6e1a_43e4_b372_2603a3cc2941.slice
6,30574068,3816544225428,-;memory: usage 20480kB, limit 20480kB, failcnt 136
6,30574069,3816544225429,-;memory+swap: usage 20480kB, limit 9007199254740988kB, failcnt 0
6,30574070,3816544225429,-;kmem: usage 0kB, limit 9007199254740988kB, failcnt 0
6,30574071,3816544225430,-;Memory cgroup stats for /kubepods.slice/kubepods-pod9eb0e64e_6e1a_43e4_b372_2603a3cc2941.slice: cache:0KB rss:0KB rss_huge:0KB shmem:0KB mapped_file:0KB dirty:0KB writeback:0KB swap:0KB workingset_refault_anon:0KB workingset_refault_file:0KB workingset_activate_anon:0KB workingset_activate_file:0KB workingset_restore_anon:0KB workingset_restore_file:0KB workingset_nodereclaim:0KB inactive_anon:0KB active_anon:0KB inactive_file:0KB active_file:0KB unevictable:0KB
6,30574072,3816544225463,-;Memory cgroup stats for /kubepods.slice/kubepods-pod9eb0e64e_6e1a_43e4_b372_2603a3cc2941.slice/docker-abfc300e93510d51d283acb2e4eb56c485821ec1b198bdc1e11fcb751d11fe9f.scope: cache:0KB rss:0KB rss_huge:0KB shmem:0KB mapped_file:0KB dirty:0KB writeback:0KB swap:0KB workingset_refault_anon:0KB workingset_refault_file:0KB workingset_activate_anon:0KB workingset_activate_file:0KB workingset_restore_anon:0KB workingset_restore_file:0KB workingset_nodereclaim:0KB inactive_anon:0KB active_anon:0KB inactive_file:0KB active_file:0KB unevictable:0KB
6,30574073,3816544225477,-;Memory cgroup stats for /kubepods.slice/kubepods-pod9eb0e64e_6e1a_43e4_b372_2603a3cc2941.slice/docker-663f6287c450aea2f849b82a30d1409059497b5de62846a286e55971d61e2650.scope: cache:0KB rss:19800KB rss_huge:0KB shmem:0KB mapped_file:0KB dirty:0KB writeback:0KB swap:0KB workingset_refault_anon:0KB workingset_refault_file:0KB workingset_activate_anon:0KB workingset_activate_file:0KB workingset_restore_anon:0KB workingset_restore_file:0KB workingset_nodereclaim:0KB inactive_anon:19800KB active_anon:0KB inactive_file:0KB active_file:0KB unevictable:0KB
6,30574074,3816544225491,-;Tasks state (memory values in pages):
6,30574075,3816544225492,-;[  pid  ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name
6,30574076,3816544225674,-;[2276312] 65535 2276312      242        1    28672        0          -998 pause
6,30574077,3816544225685,-;[2292670]     0 2292670   178320     5602   131072        0          -997 main
6,30574078,3816544226814,-;oom_reaper: reaped process 2292670 (main), now anon-rss:0kB, file-rss:0kB, shmem-rss:0kB
```

`oom_reaper: reaped process` 代表这次的oom事件结束, 后面的参数是pid和进程名.
`/kubepods.slice/kubepods-pod9eb0e64e_6e1a_43e4_b372_2603a3cc2941.slice/docker-663f6287c450aea2f849b82a30d1409059497b5de62846a286e55971d61e2650.scope` 这里面是pod的uid加containerID, 通过containerID可以找到pod的namespace和pod的名称.

### 测试用例
```shell
kubectl apply -f examples/oom-pod.yaml
```
可以看到在influxdb中有如下的数据:
```text
┃ index ┃              time              ┃ container_oom_events_total ┃          namespace           ┃           podname            ┃
┃   1030┃  1697184506653975296.0000000000┃                1.0000000000┃default                       ┃addon-elasticsearch-2-2       ┃
┃   1031┃  1697184507380657664.0000000000┃                1.0000000000┃default                       ┃addon-elasticsearch-2-1       ┃
┃   1032┃  1697184509653826048.0000000000┃                1.0000000000┃default                       ┃addon-elasticsearch-2-2       ┃
┃   1033┃  1697184509653826048.0000000000┃                1.0000000000┃default                       ┃addon-elasticsearch-2-0       ┃
┃   1034┃  1697184510374475264.0000000000┃                1.0000000000┃default                       ┃addon-elasticsearch-2-1       ┃
┃   1035┃  1697184512653128704.0000000000┃                1.0000000000┃default                       ┃addon-elasticsearch-2-0       ┃
┃   1036┃  1697184514893743104.0000000000┃                1.0000000000┃default                       ┃oom-pod 
```

### TODO
用在内核中打桩的方式取代监听`/dev/kmsg`程序