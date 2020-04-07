# 手动搭建k8s

## 准备工作

关闭 firewall、SElinux、swap



### 开启路由转发

修改`/etc/sysctl.conf`文件，添加下面的规则：

```shell
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
```

执行下面的命令立即生效：

```shell
[root@node1 ~]# sysctl -p
```



## 集群环境变量

资源

```objc
192.168.205.10    master1
192.168.205.20    master2
192.168.205.30    master2
192.168.205.105   node1
192.168.205.106   node2
192.168.205.107   node3
```



创建 env.sh 文件定义全局变量，然后将脚本拷贝到所有机器的`/usr/k8s/bin`目录

```shell
# TLS Bootstrapping 使用的Token，可以使用命令 head -c 16 /dev/urandom | od -An -t x | tr -d ' ' 生成
BOOTSTRAP_TOKEN="c803469294080520e0ae0f34c7b3de08"

# 建议使用未用的网段来定义服务网段和Pod 网段
# 服务网段(Service CIDR)，部署前路由不可达，部署后集群内部使用IP:Port可达
SERVICE_CIDR="10.254.0.0/16"
# Pod 网段(Cluster CIDR)，部署前路由不可达，部署后路由可达(flanneld 保证)
CLUSTER_CIDR="172.30.0.0/16"

# 服务端口范围(NodePort Range)
NODE_PORT_RANGE="30000-32766"

# etcd集群服务地址列表
ETCD_ENDPOINTS="https://192.168.205.10:2379,https://192.168.205.20:2379,https://192.168.205.30:2379"

# flanneld 网络配置前缀
FLANNEL_ETCD_PREFIX="/kubernetes/network"

# kubernetes 服务IP(预先分配，一般为SERVICE_CIDR中的第一个IP)
CLUSTER_KUBERNETES_SVC_IP="10.254.0.1"

# 集群 DNS 服务IP(从SERVICE_CIDR 中预先分配)
CLUSTER_DNS_SVC_IP="10.254.0.2"

# 集群 DNS 域名
CLUSTER_DNS_DOMAIN="cluster.local."

# MASTER API Server 地址
MASTER_URL="k8s-api.virtual.local"
```

为方便后面迁移，我们在集群内定义一个域名用于访问`apiserver`，在每个节点的`/etc/hosts`文件中添加记录：**192.168.205.10     k8s-api.virtual.local**

其中`192.168.205.10`为master01 的IP，暂时使用该IP 来做apiserver 的负载地址，等以后 apiserver 的负载均衡配置好后，直接替换这个IP就行



新建文件夹，放置相关k8s文件，并把刚才的变量文件移到里面

```shell
[root@tang ~]# mkdir -p /usr/k8s/bin
[root@tang ~]# cp env.sh /usr/k8s/bin/
[root@tang ~]# ls /usr/k8s/bin/
env.sh
```



## 创建CA证书和秘钥

`kubernetes` 系统各个组件需要使用`TLS`证书对通信进行加密，这里我们使用`CloudFlare`的PKI 工具集[cfssl](https://github.com/cloudflare/cfssl) 来生成Certificate Authority(CA) 证书和密钥文件， CA 是自签名的证书，用来签名后续创建的其他TLS 证书。



### 安装 CFSSL

```shell
[root@tang ~]# wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
[root@tang ~]# wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
[root@tang ~]# wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
[root@tang ~]# chmod +x cfssl*
[root@tang ~]# cp cfssl-certinfo_linux-amd64 /usr/k8s/bin/cfssl-certinfo
[root@tang ~]# cp cfssljson_linux-amd64 /usr/k8s/bin/cfssljson
[root@tang ~]# cp cfssl_linux-amd64 /usr/k8s/bin/cfssl
[root@tang ~]# ls /usr/k8s/bin/
cfssl  cfssl-certinfo  cfssljson  env.sh
[root@tang ~]# export PATH=/usr/k8s/bin:$PATH
[root@tang ~]# echo $PATH
/usr/k8s/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/home/vagrant/.local/bin:/home/vagrant/bin
[root@tang ~]# mkdir ssl && cd ssl
[root@tang ssl]# cfssl print-defaults config > config.json
[root@tang ssl]# cat config.json
{
    "signing": {
        "default": {
            "expiry": "168h"
        },
        "profiles": {
            "www": {
                "expiry": "8760h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "server auth"
                ]
            },
            "client": {
                "expiry": "8760h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "client auth"
                ]
            }
        }
    }
}

[root@tang ssl]# cfssl print-defaults csr > csr.json
[root@tang ssl]# cat csr.json
{
    "CN": "example.net",
    "hosts": [
        "example.net",
        "www.example.net"
    ],
    "key": {
        "algo": "ecdsa",
        "size": 256
    },
    "names": [
        {
            "C": "US",
            "L": "CA",
            "ST": "San Francisco"
        }
    ]
}

[root@tang ssl]# ls
config.json  csr.json
```

为了方便，将`/usr/k8s/bin`设置成环境变量，为了重启也有效，可以将上面的`export PATH=/usr/k8s/bin:$PATH`添加到`/etc/rc.local`文件中

### 创建CA

修改上面创建的`config.json`文件为`ca-config.json`

```shell
[root@tang ssl]# mv config.json ca-config.json
[root@tang ssl]# vim ca-config.json
{
    "signing": {
        "default": {
            "expiry": "87600h"
        },
        "profiles": {
            "kubernetes": {
                "expiry": "87600h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "server auth",
                    "client auth"
                ]
            }
        }
    }
}
```

> - `config.json`：可以定义多个profiles，分别指定不同的过期时间、使用场景等参数；后续在签名证书时使用某个profile；
> - `signing`: 表示该证书可用于签名其它证书；生成的ca.pem 证书中`CA=TRUE`；
> - `server auth`: 表示client 可以用该CA 对server 提供的证书进行校验；
> - `client auth`: 表示server 可以用该CA 对client 提供的证书进行验证



修改CA 证书签名请求为`ca-csr.json`

```shell
[root@tang ssl]# mv csr.json ca-csr.json
[root@tang ssl]# vim ca-csr.json
{
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "BeiJing",
            "ST": "BeiJing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
```

>- `CN`: `Common Name`，kube-apiserver 从证书中提取该字段作为请求的用户名(User Name)；浏览器使用该字段验证网站是否合法；
>- `O`: `Organization`，kube-apiserver 从证书中提取该字段作为请求用户所属的组(Group)；



生成CA 证书和私钥：

```shell
[root@tang ssl]# cfssl gencert -initca ca-csr.json | cfssljson -bare ca
2020/03/21 14:35:04 [INFO] generating a new CA key and certificate from CSR
2020/03/21 14:35:04 [INFO] generate received request
2020/03/21 14:35:04 [INFO] received CSR
2020/03/21 14:35:04 [INFO] generating key: rsa-2048
2020/03/21 14:35:05 [INFO] encoded CSR
2020/03/21 14:35:05 [INFO] signed certificate with serial number 398030474710052273213613023206555703740796869316
[root@tang ssl]# ls ca*
ca-config.json  ca.csr  ca-csr.json  ca-key.pem  ca.pem
```



### 分发证书

将生成的CA 证书、密钥文件、配置文件统一拷贝到所有机器的`/etc/kubernetes/ssl`目录下面：

```shell
[root@tang ssl]# mkdir -p /etc/kubernetes/ssl
[root@tang ssl]# cp ca* /etc/kubernetes/ssl
[root@tang ssl]# ls /etc/kubernetes/ssl/
ca-config.json  ca.csr  ca-csr.json  ca-key.pem  ca.pem
```



## Etcd 集群搭建

kubernetes 系统使用`etcd`存储所有的数据，我们这里部署3个节点的etcd 集群，这3个节点直接复用kubernetes master的3个节点，分别命名为`etcd01`、`etcd02`、`etcd03`:

- 192.168.205.10    etcd01
- 192.168.205.20    etcd02
- 192.168.205.30    etcd03



先导入开头设置的变量

```shell
[root@tang ssl]# source /usr/k8s/bin/env.sh
# 验证
[root@tang ssl]# echo $ETCD_ENDPOINTS
https://192.168.205.10:2379,https://192.168.205.20:2379,https://192.168.205.30:2379
```

在设置以下变量：

```objc
export NODE_NAME=etcd01 # 当前部署的机器名称(随便定义，只要能区分不同机器即可)
export NODE_IP=192.168.205.10 # 当前部署的机器IP
export NODE_IPS="192.168.205.10 192.168.205.20 192.168.205.30" # etcd 集群所有机器 IP
# etcd 集群间通信的IP和端口
export ETCD_NODES=etcd01=https://192.168.205.10:2380,etcd02=https://192.168.205.20:2380,etcd03=https://192.168.205.30:2380
# 导入用到的其它全局变量：ETCD_ENDPOINTS、FLANNEL_ETCD_PREFIX、CLUSTER_CIDR
# 验证
[root@tang ssl]# echo $ETCD_NODES
etcd01=https://192.168.205.10:2380,etcd02=https://192.168.205.20:2380,etcd03=https://192.168.205.30:2380
```



### 下载 etcd 二进制文件

在 [etcd](https://github.com/etcd-io/etcd) 下载最新版

```shell
[root@tang ssl]# tar -xzvf etcd-v3.3.19-linux-amd64.tar.gz
[root@tang ssl]# cp etcd-v3.3.19-linux-amd64/etcd* /usr/k8s/bin/
[root@tang ssl]# etcd --help
[root@tang ssl]# ls /usr/k8s/bin/
cfssl  cfssl-certinfo  cfssljson  env.sh  etcd  etcdctl
```



### 创建TLS 密钥和证书

为了保证通信安全，客户端(如etcdctl)与etcd 集群、etcd 集群之间的通信需要使用TLS 加密。

创建etcd 证书签名请求：

```shell
[root@tang ~]# echo ${NODE_IP}
192.168.205.10
[root@tang ~]# cat > etcd-csr.json <<EOF
{
  "CN": "etcd",
  "hosts": [
    "127.0.0.1",
    "${NODE_IP}"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF
```

> `hosts` 字段指定授权使用该证书的`etcd`节点IP



生成`etcd`证书和私钥

```shell
[root@tang ~]# cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem   -ca-key=/etc/kubernetes/ssl/ca-key.pem   -config=/etc/kubernetes/ssl/ca-config.json   -profile=kubernetes etcd-csr.json | cfssljson -bare etcd
[root@master1 ~]# ls etcd*
etcd.csr  etcd-csr.json  etcd-key.pem  etcd.pem
[root@master1 ~]# mkdir -p /etc/etcd/ssl
[root@master1 ~]# mv etcd*.pem /etc/etcd/ssl/
```



### 创建etcd 的systemd unit 文件

```shell
[root@master1 ~]# mkdir -p /var/lib/etcd  # 必须要先创建工作目录
[root@master1 ~]# cat > etcd.service <<EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/coreos

[Service]
Type=notify
WorkingDirectory=/var/lib/etcd/
ExecStart=/usr/k8s/bin/etcd \\
  --name=${NODE_NAME} \\
  --cert-file=/etc/etcd/ssl/etcd.pem \\
  --key-file=/etc/etcd/ssl/etcd-key.pem \\
  --peer-cert-file=/etc/etcd/ssl/etcd.pem \\
  --peer-key-file=/etc/etcd/ssl/etcd-key.pem \\
  --trusted-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --peer-trusted-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --initial-advertise-peer-urls=https://${NODE_IP}:2380 \\
  --listen-peer-urls=https://${NODE_IP}:2380 \\
  --listen-client-urls=https://${NODE_IP}:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls=https://${NODE_IP}:2379 \\
  --initial-cluster-token=etcd-cluster-0 \\
  --initial-cluster=${ETCD_NODES} \\
  --initial-cluster-state=new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

> - 指定`etcd`的工作目录和数据目录为`/var/lib/etcd`，需要在启动服务前创建这个目录；
> - 为了保证通信安全，需要指定etcd 的公私钥(cert-file和key-file)、Peers通信的公私钥和CA 证书(peer-cert-file、peer-key-file、peer-trusted-ca-file)、客户端的CA 证书(trusted-ca-file)；
> - `--initial-cluster-state`值为`new`时，`--name`的参数值必须位于`--initial-cluster`列表中；



### 启动etcd服务

```shell
[root@master1 ~]# mv etcd.service /etc/systemd/system/
[root@master1 ~]# systemctl daemon-reload
[root@master1 ~]# systemctl enable etcd
[root@master1 ~]# systemctl start etcd
[root@master1 ~]# systemctl status etcd
```

> 最先启动的etcd 进程会卡住一段时间，等待其他节点启动加入集群，在所有的etcd 节点重复上面的步骤，直到所有的机器etcd 服务都已经启动。



### 验证服务

部署完etcd 集群后，在任一etcd 节点上执行下面命令：

```shell
for ip in ${NODE_IPS}; do
  ETCDCTL_API=3 /usr/k8s/bin/etcdctl \
  --endpoints=https://${ip}:2379  \
  --cacert=/etc/kubernetes/ssl/ca.pem \
  --cert=/etc/etcd/ssl/etcd.pem \
  --key=/etc/etcd/ssl/etcd-key.pem \
  endpoint health; done
```

输出如下结果：

```shell
[root@master3 ssl]# for ip in ${NODE_IPS}; do
>   ETCDCTL_API=3 /usr/k8s/bin/etcdctl \
>   --endpoints=https://${ip}:2379  \
>   --cacert=/etc/kubernetes/ssl/ca.pem \
>   --cert=/etc/etcd/ssl/etcd.pem \
>   --key=/etc/etcd/ssl/etcd-key.pem \
>   endpoint health; done
https://192.168.205.10:2379 is healthy: successfully committed proposal: took = 56.99535ms
https://192.168.205.20:2379 is healthy: successfully committed proposal: took = 16.467571ms
https://192.168.205.30:2379 is healthy: successfully committed proposal: took = 11.315611ms
```



## Master 节点搭建

kubernetes master 节点包含的组件有：

- kube-apiserver
- kube-scheduler
- kube-controller-manager

目前这3个组件需要部署到同一台机器上：（后面再部署高可用的master）

- `kube-scheduler`、`kube-controller-manager` 和 `kube-apiserver` 三者的功能紧密相关；
- 同时只能有一个 `kube-scheduler`、`kube-controller-manager` 进程处于工作状态，如果运行多个，则需要通过选举产生一个 leader；

master 节点与node 节点上的Pods 通过Pod 网络通信，所以需要在master 节点上部署Flannel 网络。



### 环境变量

```shell
[root@master1 ~]# export NODE_IP=192.168.205.10 # 当前部署的master 机器IP
[root@master1 ~]# source /usr/k8s/bin/env.sh
```



### 下载最新版本的二进制文件

[k8s github](https://github.com/kubernetes/kubernetes)

```shell
[root@master1 ~]# tar -xzvf kubernetes-server-linux-amd64.tar.gz
[root@master1 ~]# cp -r kubernetes/server/bin/{kube-apiserver,kube-controller-manager,kube-scheduler,kubectl} /usr/k8s/bin/
[root@master1 ~]# ls /usr/k8s/bin/
cfssl  cfssl-certinfo  cfssljson  env.sh  etcd  etcdctl  kube-apiserver  kube-controller-manager  kube-scheduler
```



### 创建kubernetes 证书

```shell
[root@master1 ~]# cat > kubernetes-csr.json <<EOF
{
  "CN": "kubernetes",
  "hosts": [
    "127.0.0.1",
    "${NODE_IP}",
    "${MASTER_URL}",
    "${CLUSTER_KUBERNETES_SVC_IP}",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF
```

> - 如果 hosts 字段不为空则需要指定授权使用该证书的 **IP 或域名列表**，所以上面分别指定了当前部署的 master 节点主机 IP 以及apiserver 负载的内部域名
> - 还需要添加 kube-apiserver 注册的名为 `kubernetes` 的服务 IP (Service Cluster IP)，一般是 kube-apiserver `--service-cluster-ip-range` 选项值指定的网段的**第一个IP**，如 “10.254.0.1”



生成kubernetes 证书和私钥：

```shell
[root@master1 ~]# cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem \
  -ca-key=/etc/kubernetes/ssl/ca-key.pem \
  -config=/etc/kubernetes/ssl/ca-config.json \
  -profile=kubernetes kubernetes-csr.json | cfssljson -bare kubernetes
[root@master1 ~]# ls kubernetes*
kubernetes.csr  kubernetes-csr.json  kubernetes-key.pem  kubernetes.pem
[root@master1 ~]# mv kubernetes*.pem /etc/kubernetes/ssl/
[root@master1 ~]# ls /etc/kubernetes/ssl/
ca-config.json  ca.csr  ca-csr.json  ca-key.pem  ca.pem  kubernetes-key.pem  kubernetes.pem
```



### 配置和启动kube-apiserver

#### 创建kube-apiserver 使用的客户端token 文件

kubelet 首次启动时向kube-apiserver 发送TLS Bootstrapping 请求，kube-apiserver 验证请求中的token 是否与它配置的token.csv 一致，如果一致则自动为kubelet 生成证书和密钥。

```shell
[root@master1 ~]# cat > token.csv <<EOF
${BOOTSTRAP_TOKEN},kubelet-bootstrap,10001,"system:kubelet-bootstrap"
EOF
[root@master1 ~]# mv token.csv /etc/kubernetes/
```

#### 创建kube-apiserver 的systemd unit文件

```shell
[root@master1 ~]# cat > kube-apiserver.service <<EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
ExecStart=/usr/k8s/bin/kube-apiserver \\
  --admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
  --advertise-address=${NODE_IP} \\
  --bind-address=0.0.0.0 \\
  --insecure-bind-address=${NODE_IP} \\
  --authorization-mode=Node,RBAC \\
  --runtime-config=rbac.authorization.k8s.io/v1alpha1 \\
  --kubelet-https=true \\
  --enable-bootstrap-token-auth \\
  --token-auth-file=/etc/kubernetes/token.csv \\
  --service-cluster-ip-range=${SERVICE_CIDR} \\
  --service-node-port-range=${NODE_PORT_RANGE} \\
  --tls-cert-file=/etc/kubernetes/ssl/kubernetes.pem \\
  --tls-private-key-file=/etc/kubernetes/ssl/kubernetes-key.pem \\
  --client-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --service-account-key-file=/etc/kubernetes/ssl/ca-key.pem \\
  --etcd-cafile=/etc/kubernetes/ssl/ca.pem \\
  --etcd-certfile=/etc/kubernetes/ssl/kubernetes.pem \\
  --etcd-keyfile=/etc/kubernetes/ssl/kubernetes-key.pem \\
  --etcd-servers=${ETCD_ENDPOINTS} \\
  --enable-swagger-ui=true \\
  --allow-privileged=true \\
  --apiserver-count=2 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/lib/audit.log \\
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \\
  --event-ttl=1h \\
  --logtostderr=true \\
  --v=6
Restart=on-failure
RestartSec=5
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

> - 如果你安装的是**1.9.x**版本的，一定要记住上面的参数`experimental-bootstrap-token-auth`，需要替换成`enable-bootstrap-token-auth`，因为这个参数在**1.9.x**里面已经废弃掉了
> - kube-apiserver 1.6 版本开始使用 etcd v3 API 和存储格式
> - `--authorization-mode=RBAC` 指定在安全端口使用RBAC 授权模式，拒绝未通过授权的请求
> - kube-scheduler、kube-controller-manager 一般和 kube-apiserver 部署在同一台机器上，它们使用**非安全端口**和 kube-apiserver通信
> - kubelet、kube-proxy、kubectl 部署在其它 Node 节点上，如果通过**安全端口**访问 kube-apiserver，则必须先通过 TLS 证书认证，再通过 RBAC 授权
> - kube-proxy、kubectl 通过使用证书里指定相关的 User、Group 来达到通过 RBAC 授权的目的
> - 如果使用了 kubelet TLS Boostrap 机制，则不能再指定 `--kubelet-certificate-authority`、`--kubelet-client-certificate` 和 `--kubelet-client-key` 选项，否则后续 kube-apiserver 校验 kubelet 证书时出现 ”x509: certificate signed by unknown authority“ 错误
> - `--admission-control` 值必须包含 `ServiceAccount`，否则部署集群插件时会失败
> - `--bind-address` 不能为 `127.0.0.1`
> - `--service-cluster-ip-range` 指定 Service Cluster IP 地址段，该地址段不能路由可达
> - `--service-node-port-range=${NODE_PORT_RANGE}` 指定 NodePort 的端口范围
> - 缺省情况下 kubernetes 对象保存在`etcd/registry` 路径下，可以通过 `--etcd-prefix` 参数进行调整
> - kube-apiserver 1.8版本后需要在`--authorization-mode`参数中添加`Node`，即：`--authorization-mode=Node,RBAC`，否则Node 节点无法注册
> - 注意要开启审查日志功能，指定`--audit-log-path`参数是不够的，这只是指定了日志的路径，还需要指定一个审查日志策略文件：`--audit-policy-file`，我们也可以使用日志收集工具收集相关的日志进行分析。



如果提示 “unknown flag: --experimental-bootstrap-token-auth”，就根据上面的提示替换成“enable-bootstrap-token-auth”；如果提示 “--audit-policy-file”，说明没有那个文件。

审查日志策略文件内容如下：（**/etc/kubernetes/audit-policy.yaml**）

```objc
apiVersion: audit.k8s.io/v1beta1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  # Log pod changes at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      # Resource "pods" doesn't match requests to any subresource of pods,
      # which is consistent with the RBAC policy.
      resources: ["pods"]
  # Log "pods/log", "pods/status" at Metadata level
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/log", "pods/status"]

  # Don't log requests to a configmap called "controller-leader"
  - level: None
    resources:
    - group: ""
      resources: ["configmaps"]
      resourceNames: ["controller-leader"]

  # Don't log watch requests by the "system:kube-proxy" on endpoints or services
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: "" # core API group
      resources: ["endpoints", "services"]

  # Don't log authenticated requests to certain non-resource URL paths.
  - level: None
    userGroups: ["system:authenticated"]
    nonResourceURLs:
    - "/api*" # Wildcard matching.
    - "/version"

  # Log the request body of configmap changes in kube-system.
  - level: Request
    resources:
    - group: "" # core API group
      resources: ["configmaps"]
    # This rule only applies to resources in the "kube-system" namespace.
    # The empty string "" can be used to select non-namespaced resources.
    namespaces: ["kube-system"]

  # Log configmap and secret changes in all other namespaces at the Metadata level.
  - level: Metadata
    resources:
    - group: "" # core API group
      resources: ["secrets", "configmaps"]

  # Log all other resources in core and extensions at the Request level.
  - level: Request
    resources:
    - group: "" # core API group
    - group: "extensions" # Version of group should NOT be included.

  # A catch-all rule to log all other requests at the Metadata level.
  - level: Metadata
    # Long-running requests like watches that fall under this rule will not
    # generate an audit event in RequestReceived.
    omitStages:
      - "RequestReceived"
```

创建并保存 **/etc/kubernetes/audit-policy.yaml** 文件。审查日志相关可以参考 https://kubernetes.io/docs/tasks/debug-application-cluster/audit/



#### 启动kube-apiserver

```shell
[root@master1 ~]# mv kube-apiserver.service /etc/systemd/system/
[root@master1 ~]# systemctl daemon-reload
[root@master1 ~]# systemctl enable kube-apiserver
[root@master1 ~]# systemctl start kube-apiserver
[root@master1 ~]# systemctl status kube-apiserver
```



###  配置和启动kube-controller-manager

#### 创建kube-controller-manager 的systemd unit 文件

```shell
[root@master1 ~]# cat > kube-controller-manager.service <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/k8s/bin/kube-controller-manager \\
  --address=127.0.0.1 \\
  --master=http://${MASTER_URL}:8080 \\
  --allocate-node-cidrs=true \\
  --service-cluster-ip-range=${SERVICE_CIDR} \\
  --cluster-cidr=${CLUSTER_CIDR} \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem \\
  --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem \\
  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem \\
  --root-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --leader-elect=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

> - `--address` 值必须为 `127.0.0.1`，因为当前 kube-apiserver 期望 scheduler 和 controller-manager 在同一台机器
> - `--master=http://${MASTER_URL}:8080`：使用`http`(非安全端口)与 kube-apiserver 通信，需要下面的`haproxy`安装成功后才能去掉8080端口。
> - `--cluster-cidr` 指定 Cluster 中 Pod 的 CIDR 范围，该网段在各 Node 间必须路由可达(flanneld保证)
> - `--service-cluster-ip-range` 参数指定 Cluster 中 Service 的CIDR范围，该网络在各 Node 间必须路由不可达，必须和 kube-apiserver 中的参数一致
> - `--cluster-signing-*` 指定的证书和私钥文件用来签名为 TLS BootStrap 创建的证书和私钥
> - `--root-ca-file` 用来对 kube-apiserver 证书进行校验，**指定该参数后，才会在Pod 容器的 ServiceAccount 中放置该 CA 证书文件**
> - `--leader-elect=true` 部署多台机器组成的 master 集群时选举产生一处于工作状态的 `kube-controller-manager` 进程



#### 启动kube-controller-manager

```shell
[root@master1 ~]# mv kube-controller-manager.service /etc/systemd/system/
[root@master1 ~]# systemctl daemon-reload
[root@master1 ~]# systemctl enable kube-controller-manager
[root@master1 ~]# systemctl start kube-controller-manager
[root@master1 ~]# systemctl status kube-controller-manager
```



### 配置和启动kube-scheduler

#### 创建kube-scheduler 的systemd unit文件

```shell
[root@master1 ~]# cat > kube-scheduler.service <<EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/k8s/bin/kube-scheduler \\
  --address=127.0.0.1 \\
  --master=http://${MASTER_URL}:8080 \\
  --leader-elect=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

> - `--address` 值必须为 `127.0.0.1`，因为当前 kube-apiserver 期望 scheduler 和 controller-manager 在同一台机器
> - `--master=http://${MASTER_URL}:8080`：使用`http`(非安全端口)与 kube-apiserver 通信，需要下面的`haproxy`启动成功后才能去掉8080端口
> - `--leader-elect=true` 部署多台机器组成的 master 集群时选举产生一处于工作状态的 `kube-controller-manager` 进程



#### 启动kube-scheduler

```shell
[root@master1 ~]# mv kube-scheduler.service /etc/systemd/system/
[root@master1 ~]# systemctl daemon-reload
[root@master1 ~]# systemctl enable kube-scheduler
[root@master1 ~]# systemctl start kube-scheduler
[root@master1 ~]# systemctl status kube-scheduler
```



## 安装配置kubectl 命令行工具

`kubectl`默认从`~/.kube/config`配置文件中获取访问kube-apiserver 地址、证书、用户名等信息，需要正确配置该文件才能正常使用`kubectl`命令。

需要将下载的kubectl 二进制文件和生产的`~/.kube/config`配置文件拷贝到需要使用kubectl 命令的机器上。

> 比如你先在master节点上安装，这样你就可以在master节点使用`kubectl`命令行工具了，如果你想在node节点上使用(当然安装的过程肯定会用到的)，你就把master上面的`kubectl`二进制文件和`~/.kube/config`文件拷贝到对应的node节点上就行了



#### 环境变量

```shell
[root@master1 ~]# source /usr/k8s/bin/env.sh
[root@master1 ~]# export KUBE_APISERVER="https://${MASTER_URL}:6443"
```

> 注意这里的`KUBE_APISERVER`地址，因为我们还没有安装`haproxy`，所以暂时需要手动指定使用`apiserver`的6443端口，等`haproxy`安装完成后就可以用使用443端口转发到6443端口去了。



#### 下载kubectl

```shell
[root@master1 ~]# ls kubernetes/server/bin/kubectl
kubernetes/server/bin/kubectl
[root@master1 ~]# cp kubernetes/server/bin/kubectl /usr/k8s/bin/
[root@master1 ~]# kubectl version
Client Version: version.Info{Major:"1", Minor:"16", GitVersion:"v1.16.2", GitCommit:"c97fe5036ef3df2967d086711e6c0c405941e14b", GitTreeState:"clean", BuildDate:"2019-10-15T19:18:23Z", GoVersion:"go1.12.10", Compiler:"gc", Platform:"linux/amd64"}
The connection to the server localhost:8080 was refused - did you specify the right host or port?
```



#### 创建admin 证书

kubectl 与 kube-apiserver 的安全端口通信，需要为安全通信提供TLS 证书和密钥。创建admin 证书签名请求：

```shell
[root@master1 ~]# cat > admin-csr.json <<EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
EOF
```

> - 后续`kube-apiserver`使用RBAC 对客户端(如kubelet、kube-proxy、Pod)请求进行授权
> - `kube-apiserver` 预定义了一些RBAC 使用的RoleBindings，如cluster-admin 将Group `system:masters`与Role `cluster-admin`绑定，该Role 授予了调用`kube-apiserver`所有API 的权限
> - O 指定了该证书的Group 为`system:masters`，kubectl使用该证书访问`kube-apiserver`时，由于证书被CA 签名，所以认证通过，同时由于证书用户组为经过预授权的`system:masters`，所以被授予访问所有API 的劝降
> - hosts 属性值为空列表



#### 生成admin 证书和私钥：

```shell
[root@master1 ~]# cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem \
  -ca-key=/etc/kubernetes/ssl/ca-key.pem \
  -config=/etc/kubernetes/ssl/ca-config.json \
  -profile=kubernetes admin-csr.json | cfssljson -bare admin
[root@master1 ~]# ls admin*
admin.csr  admin-csr.json  admin-key.pem  admin.pem
[root@master1 ~]# mv admin*.pem /etc/kubernetes/ssl/
[root@master1 ~]# ls /etc/kubernetes/ssl/
admin-key.pem  admin.pem  ca-config.json  ca.csr  ca-csr.json  ca-key.pem  ca.pem  kubernetes-key.pem  kubernetes.pem
```



#### 创建 kubectl kubeconfig 文件

```shell
# 设置集群参数
[root@master1 ~]# kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER}
# 设置客户端认证参数
[root@master1 ~]# kubectl config set-credentials admin \
  --client-certificate=/etc/kubernetes/ssl/admin.pem \
  --embed-certs=true \
  --client-key=/etc/kubernetes/ssl/admin-key.pem \
  --token=${BOOTSTRAP_TOKEN}
# 设置上下文参数
[root@master1 ~]# kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin
# 设置默认上下文
[root@master1 ~]# kubectl config use-context kubernetes
```

> - `admin.pem`证书O 字段值为`system:masters`，`kube-apiserver` 预定义的 RoleBinding `cluster-admin` 将 Group `system:masters` 与 Role `cluster-admin` 绑定，该 Role 授予了调用`kube-apiserver` 相关 API 的权限
> - 生成的kubeconfig 被保存到 `~/.kube/config` 文件



```shell
[root@master1 ~]# kubectl version
Client Version: version.Info{Major:"1", Minor:"16", GitVersion:"v1.16.2", GitCommit:"c97fe5036ef3df2967d086711e6c0c405941e14b", GitTreeState:"clean", BuildDate:"2019-10-15T19:18:23Z", GoVersion:"go1.12.10", Compiler:"gc", Platform:"linux/amd64"}
Server Version: version.Info{Major:"1", Minor:"16", GitVersion:"v1.16.2", GitCommit:"c97fe5036ef3df2967d086711e6c0c405941e14b", GitTreeState:"clean", BuildDate:"2019-10-15T19:09:08Z", GoVersion:"go1.12.10", Compiler:"gc", Platform:"linux/amd64"}
```

> 看到 Server Version 已经有了，说明 kubectl 已经连接到了 apiserver



#### 分发 kubeconfig 文件

将`~/.kube/config`文件拷贝到运行`kubectl`命令的机器的`~/.kube/`目录下去。



### 验证master 节点

```shell
[root@master1 ~]# kubectl get cs
NAME                 AGE
scheduler            <unknown>
etcd-1               <unknown>
etcd-0               <unknown>
controller-manager   <unknown>
# 或
[root@master1 ~]# kubectl get componentstatuses
```



```shell
kubectl get nodes
```









## 部署Flannel 网络

kubernetes 要求集群内各节点能通过Pod 网段互联互通，下面我们来使用Flannel 在所有节点上创建互联互通的Pod 网段的步骤。

> 需要在所有的Node节点安装。



### 环境变量

```shell
[root@node1 ~]# export NODE_IP=192.168.205.105   # 当前部署节点的IP
# 导入全局变量
[root@node1 ~]# source /usr/k8s/bin/env.sh
```



### 创建TLS 密钥和证书

etcd 集群启用了双向TLS 认证，所以需要为flanneld 指定与etcd 集群通信的CA 和密钥。

```shell
[root@node1 ~]# mkdir -p /etc/kubernetes/ssl
# 把之前创建的 ca 证书复制到 /etc/kubernetes/ssl/
[root@node1 ~]# ls /etc/kubernetes/ssl/
ca-config.json  ca.csr  ca-csr.json  ca-key.pem  ca.pem
```

创建 flanneld 证书签名请求：

```shell
[root@node1 ~]# cat > flanneld-csr.json <<EOF
{
  "CN": "flanneld",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF
```

生成flanneld 证书和私钥：

```shell
[root@node1 ~]# cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem \
  -ca-key=/etc/kubernetes/ssl/ca-key.pem \
  -config=/etc/kubernetes/ssl/ca-config.json \
  -profile=kubernetes flanneld-csr.json | cfssljson -bare flanneld
[root@node1 ~]# ls flanneld*
flanneld.csr  flanneld-csr.json  flanneld-key.pem  flanneld.pem
[root@node1 ~]# mkdir -p /etc/flanneld/ssl
[root@node1 ~]# mv flanneld*.pem /etc/flanneld/ssl
```





### 向 etcd 写入集群Pod 网段信息

> 该步骤只需在第一次部署Flannel 网络时执行，后续在其他节点上部署Flanneld 时无需再写入该信息

```shell
[root@master1 ~]# etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/ssl/ca.pem \
  --cert-file=/etc/flanneld/ssl/flanneld.pem \
  --key-file=/etc/flanneld/ssl/flanneld-key.pem \
  set ${FLANNEL_ETCD_PREFIX}/config '{"Network":"'${CLUSTER_CIDR}'", "SubnetLen": 24, "Backend": {"Type": "vxlan"}}'
```

> 写入的 Pod 网段(${CLUSTER_CIDR}，172.30.0.0/16) 必须与`kube-controller-manager` 的 `--cluster-cidr` 选项值一致；

正常情况下将能看到一下输出：

```objc
{"Network":"172.30.0.0/16", "SubnetLen": 24, "Backend": {"Type": "vxlan"}}
```





### 安装和配置flanneld

前往[flanneld release](https://github.com/coreos/flannel/releases)页面下载的 flanneld 二进制文件：

```shell
[root@node1 ~]# mkdir flannel
[root@node1 ~]# tar -xzvf flannel-v0.12.0-linux-amd64.tar.gz -C flannel
[root@node1 ~]# cp flannel/{flanneld,mk-docker-opts.sh} /usr/k8s/bin
```

创建flanneld的systemd unit 文件

```shell
[root@node1 ~]# cat > flanneld.service << EOF
[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service

[Service]
Type=notify
ExecStart=/usr/k8s/bin/flanneld \\
  -etcd-cafile=/etc/kubernetes/ssl/ca.pem \\
  -etcd-certfile=/etc/flanneld/ssl/flanneld.pem \\
  -etcd-keyfile=/etc/flanneld/ssl/flanneld-key.pem \\
  -etcd-endpoints=${ETCD_ENDPOINTS} \\
  -etcd-prefix=${FLANNEL_ETCD_PREFIX}
ExecStartPost=/usr/k8s/bin/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/docker
Restart=on-failure

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
EOF
```

> - `mk-docker-opts.sh`脚本将分配给flanneld 的Pod 子网网段信息写入到`/run/flannel/docker` 文件中，后续docker 启动时使用这个文件中的参数值为 docker0 网桥
> - flanneld 使用系统缺省路由所在的接口和其他节点通信，对于有多个网络接口的机器(内网和公网)，可以用 `--iface` 选项值指定通信接口(上面的 systemd unit 文件没指定这个选项



### 启动flanneld

```shell
[root@node1 ~]# mv flanneld.service /etc/systemd/system/
[root@node1 ~]# systemctl daemon-reload
[root@node1 ~]# systemctl enable flanneld
[root@node1 ~]# systemctl start flanneld
[root@node1 ~]# systemctl status flanneld
```



### 检查flanneld 服务

```shell
[root@node1 ~]# ifconfig flannel.1
```



### 检查分配给各flanneld 的Pod 网段信息

```shell
# 查看集群 Pod 网段(/16)
[root@node1 ~]# etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/ssl/ca.pem \
  --cert-file=/etc/flanneld/ssl/flanneld.pem \
  --key-file=/etc/flanneld/ssl/flanneld-key.pem \
  get ${FLANNEL_ETCD_PREFIX}/config
{ "Network": "172.30.0.0/16", "SubnetLen": 24, "Backend": { "Type": "vxlan" } }
# 查看已分配的 Pod 子网段列表(/24)
[root@node1 ~]# etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/ssl/ca.pem \
  --cert-file=/etc/flanneld/ssl/flanneld.pem \
  --key-file=/etc/flanneld/ssl/flanneld-key.pem \
  ls ${FLANNEL_ETCD_PREFIX}/subnets
/kubernetes/network/subnets/172.30.58.0-24
# 查看某一 Pod 网段对应的 flanneld 进程监听的 IP 和网络参数
[root@node1 ~]# etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/ssl/ca.pem \
  --cert-file=/etc/flanneld/ssl/flanneld.pem \
  --key-file=/etc/flanneld/ssl/flanneld-key.pem \
  get ${FLANNEL_ETCD_PREFIX}/subnets/172.30.58.0-24
{"PublicIP":"192.168.1.137","BackendType":"vxlan","BackendData":{"VtepMAC":"62:fc:03:83:1b:2b"}}
```



### 确保各节点间Pod 网段能互联互通

在各个节点部署完Flanneld 后，查看已分配的Pod 子网段列表：

```shell
[root@node1 ~]# etcdctl \
  --endpoints=${ETCD_ENDPOINTS} \
  --ca-file=/etc/kubernetes/ssl/ca.pem \
  --cert-file=/etc/flanneld/ssl/flanneld.pem \
  --key-file=/etc/flanneld/ssl/flanneld-key.pem \
  ls ${FLANNEL_ETCD_PREFIX}/subnets
```





## 部署node节点

kubernetes Node 节点包含如下组件：

- flanneld
- docker
- kubelet
- kube-proxy



### 环境变量

```shell
[root@node1 ~]# source /usr/k8s/bin/env.sh
[root@node1 ~]# export KUBE_APISERVER="https://${MASTER_URL}:6443"  # // 如果你没有安装`haproxy`的话，还是需要使用6443端口的哦
[root@node1 ~]# export NODE_IP=192.168.205.105  # 当前部署的节点 IP
```

记得加上master1节点的ip

```shell
[root@node1 ~]# cat /etc/hosts
127.0.0.1       node1   node1
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
192.168.205.10     k8s-api.virtual.local
```

按照上面的步骤安装配置好flanneld



### Docker

#### 安装docker

创建 `docker.service` 文件

```shell
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.service
Wants=network-online.target

[Service]
Type=notify
# the default is not to use systemd for cgroups because the delegate issues still
# exists and systemd currently does not support the cgroup feature set required
# for containers run by docker
EnvironmentFile=-/run/flannel/docker
ExecStart=/usr/bin/dockerd --log-level=info $DOCKER_NETWORK_OPTIONS
ExecReload=/bin/kill -s HUP $MAINPID

# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity

# Uncomment TasksMax if your systemd version supports it.
# Only systemd 226 and above support this version.
#TasksMax=infinity
TimeoutStartSec=0

# set delegate yes so that systemd does not reset the cgroups of docker containers
Delegate=yes

# kill only the docker process, not all processes in the cgroup
KillMode=process

# restart the docker process if it exits prematurely
Restart=on-failure

StartLimitBurst=3

StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
```

安装

```shell
tar -xvf docker-19.03.4.tgz;cp docker/* /usr/bin/;cp docker.service /usr/lib/systemd/system/;chmod +x /usr/lib/systemd/system/docker.service;systemctl daemon-reload;systemctl enable docker.service;systemctl start docker;systemctl status docker;docker -v
```





#### 配置docker

可以用二进制或yum install 的方式来安装docker，然后修改docker 的systemd unit 文件：

```shell
EnvironmentFile=-/run/flannel/docker
ExecStart=/usr/bin/dockerd --log-level=info $DOCKER_NETWORK_OPTIONS
```

- dockerd 运行时会调用其它 docker 命令，如 docker-proxy，所以需要将 docker 命令所在的目录加到 PATH 环境变量中
- flanneld 启动时将网络配置写入到 `/run/flannel/docker` 文件中的变量 `DOCKER_NETWORK_OPTIONS`，dockerd 命令行上指定该变量值来设置 docker0 网桥参数
- 如果指定了多个 `EnvironmentFile` 选项，则必须将 `/run/flannel/docker` 放在最后(确保 docker0 使用 flanneld 生成的 bip 参数)
- 不能关闭默认开启的 `--iptables` 和 `--ip-masq` 选项
- 如果内核版本比较新，建议使用 `overlay` 存储驱动



为了加快 pull image 的速度，可以使用国内的仓库镜像服务器，同时增加下载的并发数。(如果 dockerd 已经运行，则需要重启 dockerd 生效。)

```shell
cat /etc/docker/daemon.json
{
   "max-concurrent-downloads": 10
}
```



#### 启动docker

```shell
$ systemctl daemon-reload
$ sudo systemctl stop firewalld
$ sudo systemctl disable firewalld
$ sudo iptables -F && sudo iptables -X && sudo iptables -F -t nat && sudo iptables -X -t nat
$ sudo systemctl enable docker
$ sudo systemctl start docker
```

> - 需要关闭 firewalld(centos7)/ufw(ubuntu16.04)，否则可能会重复创建 iptables 规则
> - 最好清理旧的 iptables rules 和 chains 规则
> - 执行命令：docker version，检查docker服务是否正常



### 安装和配置kubelet

kubelet 启动时向kube-apiserver 发送TLS bootstrapping 请求，需要先将bootstrap token 文件中的kubelet-bootstrap 用户赋予system:node-bootstrapper 角色，然后kubelet 才有权限创建认证请求(certificatesigningrequests)：

> kubelet就是运行在Node节点上的，所以这一步安装是在所有的Node节点上，如果你想把你的Master也当做Node节点的话，当然也可以在Master节点上安装的。

```shell
[root@node1 ~]# kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --user=kubelet-bootstrap
```

> - --user=kubelet-bootstrap 是文件 /etc/kubernetes/token.csv 中指定的用户名，同时也写入了文件 /etc/kubernetes/bootstrap.kubeconfig



另外1.8 版本中还需要为Node 请求创建一个RBAC 授权规则：

```shell
[root@node1 ~]# kubectl create clusterrolebinding kubelet-nodes --clusterrole=system:node --group=system:nodes
```

然后下载 kubelet 和 kube-proxy 二进制文件（前面下载kubernetes 目录下面其实也有）：

```shell
[root@node1 ~]# tar -xzvf kubernetes-server-linux-amd64.tar.gz
[root@node1 ~]# cd kubernetes
[root@node1 ~]# tar -xzvf  kubernetes-src.tar.gz
[root@node1 ~]# cp -r ./server/bin/{kube-proxy,kubelet} /usr/k8s/bin/
```





#### 创建kubelet bootstapping kubeconfig 文件

```shell
[root@node1 ~]# # 设置集群参数
[root@node1 ~]# kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=bootstrap.kubeconfig
[root@node1 ~]# # 设置客户端认证参数
[root@node1 ~]# kubectl config set-credentials kubelet-bootstrap \
  --token=${BOOTSTRAP_TOKEN} \
  --kubeconfig=bootstrap.kubeconfig
[root@node1 ~]# # 设置上下文参数
[root@node1 ~]# kubectl config set-context default \
  --cluster=kubernetes \
  --user=kubelet-bootstrap \
  --kubeconfig=bootstrap.kubeconfig
[root@node1 ~]# # 设置默认上下文
[root@node1 ~]# kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
[root@node1 ~]# mv bootstrap.kubeconfig /etc/kubernetes/
```

> - `--embed-certs` 为 `true` 时表示将 `certificate-authority` 证书写入到生成的 `bootstrap.kubeconfig` 文件中；
> - 设置 kubelet 客户端认证参数时**没有**指定秘钥和证书，后续由 `kube-apiserver` 自动生成；



#### 创建kubelet 的systemd unit 文件

先创建工作目录

```shell
[root@node1 ~]# mkdir -p /var/lib/kubelet # 必须先创建工作目录
[root@node1 ~]# cat > kubelet.service <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStart=/usr/k8s/bin/kubelet \\
  --fail-swap-on=false \\
  --cgroup-driver=cgroupfs \\
  --address=${NODE_IP} \\
  --hostname-override=${NODE_IP} \\
  --bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \\
  --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \\
  --cert-dir=/etc/kubernetes/ssl \\
  --cluster-dns=${CLUSTER_DNS_SVC_IP} \\
  --cluster-domain=${CLUSTER_DNS_DOMAIN} \\
  --hairpin-mode promiscuous-bridge \\
  --serialize-image-pulls=false \\
  --logtostderr=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

> > **请仔细阅读下面的注意事项，不然可能会启动失败**。
>
> - `--fail-swap-on`参数，这个一定要注意，**Kubernetes 1.8开始要求关闭系统的Swap**，如果不关闭，默认配置下kubelet将无法启动，也可以通过kubelet的启动参数`–fail-swap-on=false`来避免该问题
> - `--cgroup-driver`参数，kubelet 用来维护主机的的 cgroups 的，默认是`cgroupfs`，但是这个地方的值需要你根据docker 的配置来确定（`docker info |grep cgroup`）
> - `-address` 不能设置为 `127.0.0.1`，否则后续 Pods 访问 kubelet 的 API 接口时会失败，因为 Pods 访问的 `127.0.0.1`指向自己而不是 kubelet
> - 如果设置了 `--hostname-override` 选项，则 `kube-proxy` 也需要设置该选项，否则会出现找不到 Node 的情况
> - `--experimental-bootstrap-kubeconfig` 指向 bootstrap kubeconfig 文件，kubelet 使用该文件中的用户名和 token 向 kube-apiserver 发送 TLS Bootstrapping 请求
> - 管理员通过了 CSR 请求后，kubelet 自动在 `--cert-dir` 目录创建证书和私钥文件(`kubelet-client.crt` 和 `kubelet-client.key`)，然后写入 `--kubeconfig` 文件(自动创建 `--kubeconfig` 指定的文件)
> - 建议在 `--kubeconfig` 配置文件中指定 `kube-apiserver` 地址，如果未指定 `--api-servers` 选项，则必须指定 `--require-kubeconfig` 选项后才从配置文件中读取 kue-apiserver 的地址，否则 kubelet 启动后将找不到 kube-apiserver (日志中提示未找到 API Server），`kubectl get nodes` 不会返回对应的 Node 信息
> - `--cluster-dns` 指定 kubedns 的 Service IP(可以先分配，后续创建 kubedns 服务时指定该 IP)，`--cluster-domain` 指定域名后缀，这两个参数同时指定后才会生效



#### 启动kubelet

```shell
[root@node1 ~]# mv kubelet.service /etc/systemd/system/kubelet.service
[root@node1 ~]# systemctl daemon-reload
[root@node1 ~]# systemctl enable kubelet
[root@node1 ~]# systemctl start kubelet
[root@node1 ~]# systemctl status kubelet
```



#### 通过kubelet 的TLS 证书请求

kubelet 首次启动时向kube-apiserver 发送证书签名请求，必须通过后kubernetes 系统才会将该 Node 加入到集群。查看未授权的CSR 请求：

```shell
[root@node1 ~]# kubectl get csr
NAME                                                   AGE   REQUESTOR           CONDITION
node-csr-NkPKF90rnnxJbTCfCU7V9z81a1o8njqp1zRXjI51hlw   10m   kubelet-bootstrap   Pending
[root@node1 ~]# kubectl get nodes
No resources found in default namespace.
```

通过CSR 请求：

```shell
[root@node1 ~]# kubectl certificate approve node-csr-NkPKF90rnnxJbTCfCU7V9z81a1o8njqp1zRXjI51hlw
certificatesigningrequest.certificates.k8s.io/node-csr-NkPKF90rnnxJbTCfCU7V9z81a1o8njqp1zRXjI51hlw approved
[root@node1 ~]# kubectl get nodes
NAME           STATUS   ROLES    AGE   VERSION
10.253.62.17   Ready    <none>   20s   v1.16.2
```

自动生成了kubelet kubeconfig 文件和公私钥：

```shell
[root@node1 ~]# ls -l /etc/kubernetes/kubelet.kubeconfig
-rw------- 1 root root 2240 Mar 30 16:40 /etc/kubernetes/kubelet.kubeconfig
[root@node1 ~]# ls -l /etc/kubernetes/ssl/kubelet*
-rw------- 1 root root 1273 Mar 30 16:40 /etc/kubernetes/ssl/kubelet-client-2020-03-30-16-40-16.pem
lrwxrwxrwx 1 root root   58 Mar 30 16:40 /etc/kubernetes/ssl/kubelet-client-current.pem -> /etc/kubernetes/ssl/k  ubelet-client-2020-03-30-16-40-16.pem
-rw-r--r-- 1 root root 2181 Mar 30 16:27 /etc/kubernetes/ssl/kubelet.crt
-rw------- 1 root root 1679 Mar 30 16:27 /etc/kubernetes/ssl/kubelet.key
```



### 配置kube-proxy

#### 创建kube-proxy 证书签名请求：

```shell
[root@node1 ~]# cat > kube-proxy-csr.json <<EOF
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF
```

> - CN 指定该证书的 User 为 `system:kube-proxy`
> - `kube-apiserver` 预定义的 RoleBinding `system:node-proxier` 将User `system:kube-proxy` 与 Role `system:node-proxier`绑定，该 Role 授予了调用 `kube-apiserver` Proxy 相关 API 的权限
> - hosts 属性值为空列表



#### 生成kube-proxy 客户端证书和私钥

```shell
[root@node1 ~]# cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem \
  -ca-key=/etc/kubernetes/ssl/ca-key.pem \
  -config=/etc/kubernetes/ssl/ca-config.json \
  -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy
[root@node1 ~]# ls kube-proxy*
kube-proxy.csr  kube-proxy-csr.json  kube-proxy-key.pem  kube-proxy.pem
[root@node1 ~]# mv kube-proxy*.pem /etc/kubernetes/ssl/
```



#### 创建kube-proxy kubeconfig 文件

```shell
$ # 设置集群参数
$ kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-proxy.kubeconfig
$ # 设置客户端认证参数
$ kubectl config set-credentials kube-proxy \
  --client-certificate=/etc/kubernetes/ssl/kube-proxy.pem \
  --client-key=/etc/kubernetes/ssl/kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig
$ # 设置上下文参数
$ kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig
$ # 设置默认上下文
$ kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
$ mv kube-proxy.kubeconfig /etc/kubernetes/
```

> - 设置集群参数和客户端认证参数时 `--embed-certs` 都为 `true`，这会将 `certificate-authority`、`client-certificate` 和 `client-key` 指向的证书文件内容写入到生成的 `kube-proxy.kubeconfig` 文件中
> - `kube-proxy.pem` 证书中 CN 为 `system:kube-proxy`，`kube-apiserver` 预定义的 RoleBinding `cluster-admin` 将User `system:kube-proxy` 与 Role `system:node-proxier` 绑定，该 Role 授予了调用 `kube-apiserver` Proxy 相关 API 的权限



#### 创建kube-proxy 的systemd unit 文件

```shell
$ mkdir -p /var/lib/kube-proxy # 必须先创建工作目录
$ cat > kube-proxy.service <<EOF
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
WorkingDirectory=/var/lib/kube-proxy
ExecStart=/usr/k8s/bin/kube-proxy \\
  --bind-address=${NODE_IP} \\
  --hostname-override=${NODE_IP} \\
  --cluster-cidr=${SERVICE_CIDR} \\
  --kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig \\
  --logtostderr=true \\
  --v=2
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
```

> - `--hostname-override` 参数值必须与 kubelet 的值一致，否则 kube-proxy 启动后会找不到该 Node，从而不会创建任何 iptables 规则
> - `--cluster-cidr` 必须与 kube-apiserver 的 `--service-cluster-ip-range` 选项值一致
> - kube-proxy 根据 `--cluster-cidr` 判断集群内部和外部流量，指定 `--cluster-cidr` 或 `--masquerade-all` 选项后 kube-proxy 才会对访问 Service IP 的请求做 SNAT
> - `--kubeconfig` 指定的配置文件嵌入了 kube-apiserver 的地址、用户名、证书、秘钥等请求和认证信息
> - 预定义的 RoleBinding `cluster-admin` 将User `system:kube-proxy` 与 Role `system:node-proxier` 绑定，该 Role 授予了调用 `kube-apiserver` Proxy 相关 API 的权限



#### 启动kube-proxy

```shell
$ mv kube-proxy.service /etc/systemd/system/
$ systemctl daemon-reload
$ systemctl enable kube-proxy
$ systemctl start kube-proxy
$ systemctl status kube-proxy
```



## 验证集群功能

定义yaml 文件：（将下面内容保存为：nginx-ds.yaml）

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-ds
  labels:
    app: nginx-ds
spec:
  type: NodePort
  selector:
    app: nginx-ds
  ports:
  - name: http
    port: 80
    targetPort: 80
---
apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: nginx-ds
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  template:
    metadata:
      labels:
        app: nginx-ds
    spec:
      containers:
      - name: my-nginx
        image: nginx:1.7.9
        ports:
        - containerPort: 80
```

创建 Pod 和服务：

```shell
$ kubectl create -f nginx-ds.yml
service "nginx-ds" created
daemonset "nginx-ds" created
```

执行下面的命令查看Pod 和SVC：

```shell
$ kubectl get pods -o wide
NAME             READY     STATUS    RESTARTS   AGE       IP           NODE
nginx-ds-f29zt   1/1       Running   0          23m       172.17.0.2   192.168.1.170
$ kubectl get svc
NAME         TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)        AGE
nginx-ds     NodePort    10.254.6.249   <none>        80:30813/TCP   24m
```

可以看到：

- 服务IP：10.254.6.249
- 服务端口：80
- NodePort端口：30813

在所有 Node 上执行：

```
$ curl 10.254.6.249
$ curl 192.168.1.170:30813
```

执行上面的命令预期都会输出nginx 欢迎页面内容，表示我们的Node 节点正常运行了。

还可以使用 `kubelet describe pod podname` 查看详细信息，或者使用 `journalctl -u kubelet -f`



如果要更换kubelet镜像地址，可以在 `/etc/systemd/system/kubelet.service` 里增加参数 `--pod-infra-container-image=cnych/pause-amd:64:3.0 \`，然后 `systemctl daemon-reload;systemctl restart kubelet`





```shell
kubectl get all
```



## 部署kubedns 插件

官方目录：https://github.com/kubernetes/kubernetes/tree/v1.8.2/cluster/addons/dns

切换到自己使用的版本，然后找到 `kube-dns.yaml.base` 文件。

找到 `clusterIP: __PILLAR__DNS__SERVER__` 行，改为开头 env.sh 里设置的IP: `clusterIP: 10.254.0.2`；找到 `image` ，替换镜像地址；找到 `--domain=__PILLAR__DNS__DOMAIN__.` 替换开头 env.sh 里设置的DNS域名:`cluster.local.`；找到 `--server=/__PILLAR__DNS__DOMAIN__/127.0.0.1#10053` 替换为`--server=/cluster.local/127.0.0.1#10053` ；把

```shell
- --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.__PILLAR__DNS__DOMAIN__,5,SRV
- --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.__PILLAR__DNS__DOMAIN__,5,SRV
```

替换成

```shell
- --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,SRV
- --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,SRV
```



新建文件 `kube-dns.yaml`

```shell
# Copyright 2016 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Should keep target in cluster/addons/dns-horizontal-autoscaler/dns-horizontal-autoscaler.yaml
# in sync with this file.

# __MACHINE_GENERATED_WARNING__

apiVersion: v1
kind: Service
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
    kubernetes.io/name: "KubeDNS"
spec:
  selector:
    k8s-app: kube-dns
  clusterIP: 10.254.0.2
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  # replicas: not specified here:
  # 1. In order to make Addon Manager do not reconcile this replicas parameter.
  # 2. Default is 1.
  # 3. Will be tuned in real time if DNS horizontal auto-scaling is turned on.
  strategy:
    rollingUpdate:
      maxSurge: 10%
      maxUnavailable: 0
  selector:
    matchLabels:
      k8s-app: kube-dns
  template:
    metadata:
      labels:
        k8s-app: kube-dns
      annotations:
        seccomp.security.alpha.kubernetes.io/pod: 'docker/default'
        prometheus.io/port: "10054"
        prometheus.io/scrape: "true"
    spec:
      priorityClassName: system-cluster-critical
      securityContext:
        supplementalGroups: [ 65534 ]
        fsGroup: 65534
      tolerations:
      - key: "CriticalAddonsOnly"
        operator: "Exists"
      volumes:
      - name: kube-dns-config
        configMap:
          name: kube-dns
          optional: true
      containers:
      - name: kubedns
        image: k8s.gcr.io/k8s-dns-kube-dns:1.14.13
        resources:
          # TODO: Set memory limits when we've profiled the container for large
          # clusters, then set request = limit to keep this container in
          # guaranteed class. Currently, this container falls into the
          # "burstable" category so the kubelet doesn't backoff from restarting it.
          limits:
            memory: __PILLAR__DNS__MEMORY__LIMIT__
          requests:
            cpu: 100m
            memory: 70Mi
        livenessProbe:
          httpGet:
            path: /healthcheck/kubedns
            port: 10054
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        readinessProbe:
          httpGet:
            path: /readiness
            port: 8081
            scheme: HTTP
          # we poll on pod startup for the Kubernetes master service and
          # only setup the /readiness HTTP server once that's available.
          initialDelaySeconds: 3
          timeoutSeconds: 5
        args:
        - --domain=cluster.local..
        - --dns-port=10053
        - --config-dir=/kube-dns-config
        - --v=2
        env:
        - name: PROMETHEUS_PORT
          value: "10055"
        ports:
        - containerPort: 10053
          name: dns-local
          protocol: UDP
        - containerPort: 10053
          name: dns-tcp-local
          protocol: TCP
        - containerPort: 10055
          name: metrics
          protocol: TCP
        volumeMounts:
        - name: kube-dns-config
          mountPath: /kube-dns-config
      - name: dnsmasq
        image: k8s.gcr.io/k8s-dns-dnsmasq-nanny:1.14.13
        livenessProbe:
          httpGet:
            path: /healthcheck/dnsmasq
            port: 10054
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        args:
        - -v=2
        - -logtostderr
        - -configDir=/etc/k8s/dns/dnsmasq-nanny
        - -restartDnsmasq=true
        - --
        - -k
        - --cache-size=1000
        - --no-negcache
        - --dns-loop-detect
        - --log-facility=-
        - --server=/cluster.local/127.0.0.1#10053
        - --server=/in-addr.arpa/127.0.0.1#10053
        - --server=/ip6.arpa/127.0.0.1#10053
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        # see: https://github.com/kubernetes/kubernetes/issues/29055 for details
        resources:
          requests:
            cpu: 150m
            memory: 20Mi
        volumeMounts:
        - name: kube-dns-config
          mountPath: /etc/k8s/dns/dnsmasq-nanny
      - name: sidecar
        image: k8s.gcr.io/k8s-dns-sidecar:1.14.13
        livenessProbe:
          httpGet:
            path: /metrics
            port: 10054
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        args:
        - --v=2
        - --logtostderr
        - --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,SRV
        - --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,SRV
        ports:
        - containerPort: 10054
          name: metrics
          protocol: TCP
        resources:
          requests:
            memory: 20Mi
            cpu: 10m
      dnsPolicy: Default  # Don't use cluster DNS.
      serviceAccountName: kube-dns
```

创建dns

```shell
kubectl create -f kube-dns.yaml
```

成功后将会看到

```objc
service "kube-dns" created
serviceaccount "kube-dns" created
configmap "kube-dns" created
deployment "kube-dns" created
```

如果使用 `kubectl get pods` 看不到，那是因为上面的 namespace 是在 kube-system 中创建的，所以需要指定`kubectl get pods -n kube-system`



```shell
kubectl get svc -n kube-system
```





### 检查kubedns 功能

新建一个Deployment

```shell
$ cat > my-nginx.yaml<<EOF
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: my-nginx
spec:
  replicas: 2
  template:
    metadata:
      labels:
        run: my-nginx
    spec:
      containers:
      - name: my-nginx
        image: nginx:1.7.9
        ports:
        - containerPort: 80
EOF
$ kubectl create -f my-nginx.yaml
deployment "my-nginx" created
$ kubectl get pods
$ kubectl get pods -o wide
```

Expose 该Deployment，生成my-nginx 服务

```shell
$ kubectl expose deploy my-nginx
$ kubectl get services
NAME         TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.254.0.1      <none>        443/TCP   1d
my-nginx     ClusterIP   10.254.32.162   <none>        80/TCP    56s
```

然后创建另外一个Pod，查看`/etc/resolv.conf`是否包含`kubelet`配置的`--cluster-dns` 和`--cluster-domain`，是否能够将服务`my-nginx` 解析到上面显示的CLUSTER-IP `10.254.32.162`上

```shell
$ cat > pod-nginx.yaml<<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx:1.7.9
    ports:
    - containerPort: 80
EOF
$ kubectl create -f pod-nginx.yaml
pod "nginx" created
$ kubectl get pods
# 把node节点的主机名和 IP加到master 中的hosts 中

$ kubectl exec  nginx -i -t -- /bin/bash
root@nginx:/# cat /etc/resolv.conf
nameserver 10.254.0.2
search default.svc.cluster.local. svc.cluster.local. cluster.local.
options ndots:5
```



## 部署CoreDNS

### 下载部署脚本
下载地址 https://github.com/coredns/deployment/tree/master/kubernetes

```shell
wget https://raw.githubusercontent.com/coredns/deployment/master/kubernetes/coredns.yaml.sed
wget https://raw.githubusercontent.com/coredns/deployment/master/kubernetes/deploy.sh
```



### 生成yaml配置文件

```shell
./deploy.sh -r 10.254.0.0/16 -i 10.254.0.2 -d cluster.local. -t coredns.yaml.sed -s > coredns.yaml
```

- -r service的cidr
- -i DNS服务的ip地址
- -d DNS服务域名

 如果报错，可能需要安装 jq

```shell
[root@localhost ~]# wget http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
[root@localhost ~]# rpm -ivh epel-release-latest-7.noarch.rpm
[root@localhost ~]# yum repolist      ##检查是否已添加至源列表
```

jq的安装

可以从https://pkgs.org/centos-7/epel-x86_64/jq-1.5-1.el7.x86_64.rpm.html下载

不过依赖太麻烦，还是装epel源，如上

然后 `yum install jq` 就OK了



### 部署COREDNS

如果已经部署了kube-dns，需要手动删除

```shell
kubectl delete --namespace=kube-system deployment kube-dns
kubectl create -f coredns.yaml
```

### 查看服务状态

```shell
root@ecp-k8s-node1:[/root/ssl]kubectl get pods --namespace=kube-system
NAME                       READY   STATUS              RESTARTS   AGE
coredns-59845f77f8-z4vvk   0/1     ContainerCreating   0          95m
kubectl get pods -n kube-system -o wide
```



```shell
kubectl describe pod coredns-59845f77f8-8vc97 -n kube-system
```











## 部署Dashboard 插件

[Dashboard官网](https://github.com/kubernetes/kubernetes/tree/release-1.16/cluster/addons/dashboard)

里的 https://github.com/kubernetes/dashboard ，根据连接下载 recommended.yaml 文件保存为 dashboard-controller.yaml，并准备好里面需要的镜像。或者替换镜像，保存到node01上。

```yaml
# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

apiVersion: v1
kind: Namespace
metadata:
  name: kubernetes-dashboard

---

apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard

---

kind: Service
apiVersion: v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  type: NodePort
  ports:
    - port: 443
      targetPort: 8443
  selector:
    k8s-app: kubernetes-dashboard

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-certs
  namespace: kubernetes-dashboard
type: Opaque

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-csrf
  namespace: kubernetes-dashboard
type: Opaque
data:
  csrf: ""

---

apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-key-holder
  namespace: kubernetes-dashboard
type: Opaque

---

kind: ConfigMap
apiVersion: v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard-settings
  namespace: kubernetes-dashboard

---

kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
rules:
  # Allow Dashboard to get, update and delete Dashboard exclusive secrets.
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["kubernetes-dashboard-key-holder", "kubernetes-dashboard-certs", "kubernetes-dashboard-csrf"]
    verbs: ["get", "update", "delete"]
    # Allow Dashboard to get and update 'kubernetes-dashboard-settings' config map.
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["kubernetes-dashboard-settings"]
    verbs: ["get", "update"]
    # Allow Dashboard to get metrics.
  - apiGroups: [""]
    resources: ["services"]
    resourceNames: ["heapster", "dashboard-metrics-scraper"]
    verbs: ["proxy"]
  - apiGroups: [""]
    resources: ["services/proxy"]
    resourceNames: ["heapster", "http:heapster:", "https:heapster:", "dashboard-metrics-scraper", "http:dashboard-metrics-scraper"]
    verbs: ["get"]

---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
rules:
  # Allow Metrics Scraper to get metrics from the Metrics server
  - apiGroups: ["metrics.k8s.io"]
    resources: ["pods", "nodes"]
    verbs: ["get", "list", "watch"]

---

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kubernetes-dashboard
subjects:
  - kind: ServiceAccount
    name: kubernetes-dashboard
    namespace: kubernetes-dashboard

---

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubernetes-dashboard
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubernetes-dashboard
subjects:
  - kind: ServiceAccount
    name: kubernetes-dashboard
    namespace: kubernetes-dashboard

---

kind: Deployment
apiVersion: apps/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kubernetes-dashboard
spec:
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      k8s-app: kubernetes-dashboard
  template:
    metadata:
      labels:
        k8s-app: kubernetes-dashboard
    spec:
      containers:
        - name: kubernetes-dashboard
          image: kubernetesui/dashboard:v2.0.0-rc6
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8443
              protocol: TCP
          args:
            - --auto-generate-certificates
            - --namespace=kubernetes-dashboard
            # Uncomment the following line to manually specify Kubernetes API server Host
            # If not specified, Dashboard will attempt to auto discover the API server and connect
            # to it. Uncomment only if the default does not work.
            # - --apiserver-host=http://my-address:port
          volumeMounts:
            - name: kubernetes-dashboard-certs
              mountPath: /certs
              # Create on-disk volume to store exec logs
            - mountPath: /tmp
              name: tmp-volume
          livenessProbe:
            httpGet:
              scheme: HTTPS
              path: /
              port: 8443
            initialDelaySeconds: 30
            timeoutSeconds: 30
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsUser: 1001
            runAsGroup: 2001
      volumes:
        - name: kubernetes-dashboard-certs
          secret:
            secretName: kubernetes-dashboard-certs
        - name: tmp-volume
          emptyDir: {}
      serviceAccountName: kubernetes-dashboard
      nodeSelector:
        "beta.kubernetes.io/os": linux
      # Comment the following tolerations if Dashboard must not be deployed on master
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule

---

kind: Service
apiVersion: v1
metadata:
  labels:
    k8s-app: dashboard-metrics-scraper
  name: dashboard-metrics-scraper
  namespace: kubernetes-dashboard
spec:
  ports:
    - port: 8000
      targetPort: 8000
  selector:
    k8s-app: dashboard-metrics-scraper

---

kind: Deployment
apiVersion: apps/v1
metadata:
  labels:
    k8s-app: dashboard-metrics-scraper
  name: dashboard-metrics-scraper
  namespace: kubernetes-dashboard
spec:
  replicas: 1
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      k8s-app: dashboard-metrics-scraper
  template:
    metadata:
      labels:
        k8s-app: dashboard-metrics-scraper
      annotations:
        seccomp.security.alpha.kubernetes.io/pod: 'runtime/default'
    spec:
      containers:
        - name: dashboard-metrics-scraper
          image: kubernetesui/metrics-scraper:v1.0.3
          ports:
            - containerPort: 8000
              protocol: TCP
          livenessProbe:
            httpGet:
              scheme: HTTP
              path: /
              port: 8000
            initialDelaySeconds: 30
            timeoutSeconds: 30
          volumeMounts:
          - mountPath: /tmp
            name: tmp-volume
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsUser: 1001
            runAsGroup: 2001
      serviceAccountName: kubernetes-dashboard
      nodeSelector:
        "beta.kubernetes.io/os": linux
      # Comment the following tolerations if Dashboard must not be deployed on master
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      volumes:
        - name: tmp-volume
          emptyDir: {}
```



### 创建

```shell
kubectl create -f dashboard-controller.yaml
# 检查
root@ecp-k8s-node1:[/root/ssl]kubectl get pods -n kubernetes-dashboard
NAME                                         READY   STATUS             RESTARTS   AGE
dashboard-metrics-scraper-7b8b58dc8b-cm6w7   0/1     ImagePullBackOff   0          2m12s
kubernetes-dashboard-5f5f847d57-xdxjb        0/1     ImagePullBackOff   0          2m12s


root@ecp-k8s-node1:[/root/ssl]kubectl get services kubernetes-dashboard -n kubernetes-dashboard
NAME                   TYPE       CLUSTER-IP     EXTERNAL-IP   PORT(S)         AGE
kubernetes-dashboard   NodePort   10.254.86.59   <none>        443:30776/TCP   76s

root@ecp-k8s-node1:[/root/ssl]kubectl get svc -n kubernetes-dashboard
NAME                        TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)         AGE
dashboard-metrics-scraper   ClusterIP   10.254.19.38     <none>        8000/TCP        3m27s
kubernetes-dashboard        NodePort    10.254.159.127   <none>        443:32035/TCP   3m27s
```



### 访问

```shell
https://10.253.62.17:32035
```

