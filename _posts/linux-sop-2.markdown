---
layout:     post
title:      "[Linux SOP] Linux 部署及安全实践指南 (其二)"
date:       2025-9-29 19:20:00
author:     "Rainyin"
catalog: true
---
> 本文源自 linuxdo @Hantong，因作者已删帖所以在此留存备份以便查看。

*   Current version: v0.1.2
*   Last updated: 2025.3.23 16:50:00, UTC+8

本部分涉及一些常见应用部署及安全实践.

以下教程涉及的命令均在 **Debian** 11 / 12 内验证, 理论兼容 Ubuntu. ~~不会吧, 你还在用 CentOS?~~ 全部命令非特别说明均默认在 **root** 用户下执行.

**此处约定**: `{}` 及其括起来的内容为根据你实际情况需要替换的文本内容, 括起来的内容为说明, 如 `ssh {user}@{server ip}` 为 ssh 连接服务器的命令, 假设用户为 `root`, 服务器 IP 为 `114.5.1.4`, 则为 `ssh root@114.5.1.4`.

## 0. 一些习惯

### 0.1. 将 `/data` 作为工作目录

```sh
mkdir /data
```

*   编译工作目录为 `/data/compile`
*   网页目录为 `/data/www`
*   …

### 0.2. `/opt` 目录

所有单执行文件的应用, 或者各类配置文件, 统一放置到此处, 后面迁移非常方便.

---

## 1. Docker

官方参考文档: [Debian | Docker Docs](https://docs.docker.com/engine/install/debian/#installation-methods)

```sh
# Uninstall old versions
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt-get remove $pkg; done

# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

# Install the Docker packages.
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Verify that the installation is successful by running the hello-world image
sudo docker run hello-world
```

### 1.1 安全实践: **Docker 干预 iptables 导致异常暴露端口的问题**

安装 Docker 后, 务必编辑 `/etc/docker/daemon.json`(没有就新建一个), 设置 `ip` 为 `127.0.0.1`, 防止 docker 自己修改了 iptable 导致 ufw 失效(或者说不受 ufw 管了).

国外服务器自行替换 dns 为 `1.1.1.1`, `8.8.8.8`:

```sh
cat <<'EOF' > /etc/docker/daemon.json
{
    "dns":[
        "119.29.29.29",
        "223.5.5.5"
    ],
    "ip":"127.0.0.1"
}
EOF
```

注意: 亲测不能修改 `/lib/systemd/system/docker.service` 加上 `--iptables=false`, 否则 Docker 无法启动. 修改 `/etc/docker/daemon.json` 加上 `{ "iptables" : false }` 本质一样.

Ref: [顾佳凯的网络日志 | Docker容器服务不受防火墙限制？](https://blog.gujiakai.top/2023/03/will-docker-container-be-limited-by-firewall.html)
Ref: [14.04 - Uncomplicated Firewall (UFW) is not blocking anything when using Docker - Ask Ubuntu](https://askubuntu.com/questions/652556/uncomplicated-firewall-ufw-is-not-blocking-anything-when-using-docker)
Ref: [Packet filtering and firewalls | Docker Docs](https://docs.docker.com/network/packet-filtering-firewalls/)

### 1.2. 配置 Docker 容器的 IPv6 支持

```sh
cat <<'EOF' > /etc/docker/daemon.json
{
    "ipv6":true,
    "fixed-cidr-v6": "2001:db8::/64",
    "ip":"127.0.0.1"
}
EOF
```

执行 `systemctl daemon-reload && systemctl restart docker` 重启 Docker.

**风险提示**

*   已知对于部分机器, 若已 DD 系统, 且开启 IPv6, 会出路由问题导致机器失联.

    需要手动配置路由, 如修改 `/etc/network/interfaces` (假设网卡名为 `eth0`):

    ```plaintext
    auto eth0
    
    iface eth0 inet dhcp
    
    iface eth0 inet6 dhcp
      post-up ip -6 route add default dev eth0 metric 100
    ```

### 1.3. 更改 Docker 默认的内网网段

毕竟有时候会和实际的内网冲突.

```sh
cat <<'EOF' > /etc/docker/daemon.json
{
    "bip": "192.168.233.1/24",
    "fixed-cidr": "192.168.233.0/25",
    "mtu": 1500,
    "default-gateway": "192.168.233.254",
    "dns":[
        "223.5.5.5",
        "223.6.6.6"
    ],
    "ipv6":true,
    "fixed-cidr-v6": "2001:db8::/64",
    "ip":"127.0.0.1"
}
EOF
```

`bip` 就是宿主机地址, `fixed-cidr` 就是你想要的内网 CIDR, `default-gateway` 就是默认路由地址. 这三个 **缺一不可** (血泪教训: 没写 `default-gateway`, 导致容器内无法访问外部网络)

执行 `systemctl daemon-reload && systemctl restart docker` 重启 Docker.

### 1.4. 代理 (含 Docker 宿主本体及容器内部)

```sh
# 自己根据实际情况修改
export DOCKER_PROXY="http://127.0.0.1:11100"
export DOCKER_NO_PROXY="localhost,127.0.0.1,.edu.cn"

sudo mkdir -p /etc/systemd/system/docker.service.d

cat <<EOF > /etc/systemd/system/docker.service.d/proxy.conf
[Service]
Environment="HTTP_PROXY=$DOCKER_PROXY"
Environment="HTTPS_PROXY=$DOCKER_PROXY"
Environment="NO_PROXY=$DOCKER_NO_PROXY"
EOF

mkdir ~/.docker
cat <<EOF > ~/.docker/config.json
{
    "proxies": {
        "default": {
            "httpProxy": "$DOCKER_PROXY",
            "httpsProxy": "$DOCKER_PROXY",
            "noProxy": "$DOCKER_NO_PROXY"
        }
    }
}
EOF
```

执行 `systemctl daemon-reload && systemctl restart docker` 重启 Docker.

### 1.5. Rootless Docker (暂不完善, 仅供参考)

对于极致追求安全的场景, 需要以非 root 用户运行 Docker, 参考: [Rootless mode | Docker Docs](https://docs.docker.com/engine/security/rootless/)

以下命令均为以普通用户身份执行.

```sh
sudo apt install uidmap
# 检查 slirp4netns 是否安装了
slirp4netns --version
# 关闭 root 身份运行的 Docker, 如果有的话
sudo systemctl disable --now docker.service docker.socket
sudo rm /var/run/docker.sock
# 安装
dockerd-rootless-setuptool.sh install
# 启动
systemctl --user enable --now docker
# 默认使用 rootless
docker context use rootless
```

前面所述 `1.4. 代理` 配置中:

```sh
export DOCKER_PROXY="http://127.0.0.1:11100"
export DOCKER_NO_PROXY="localhost,127.0.0.1,.edu.cn"

# mkdir -p ~/.config/systemd
# mkdir -p ~/.config/systemd/user
mkdir -p ~/.config/systemd/user/docker.service.d

cat <<'EOF' > ~/.config/systemd/user/docker.service.d/proxy.conf
[Service]
Environment="HTTP_PROXY=http://192.168.233.2:10024/"
Environment="HTTPS_PROXY=http://192.168.233.2:10024/"
Environment="NO_PROXY=localhost,127.0.0.1,.example.com"
EOF

mkdir ~/.docker
cat <<EOF > ~/.docker/config.json
{
    "currentContext": "rootless",
    "proxies": {
        "default": {
            "httpProxy": "$DOCKER_PROXY",
            "httpsProxy": "$DOCKER_PROXY",
            "noProxy": "$DOCKER_NO_PROXY"
        }
    }
}
EOF
```

其中 `192.168.233.2` 是宿主机.

此外前面所述 `1.3 修改内网网段` 也得改:

```sh
cat <<'EOF' > ~/.config/systemd/user/docker.service.d/override.conf
[Service]
Environment="DOCKERD_ROOTLESS_ROOTLESSKIT_FLAGS=--cidr=192.168.233.0/24"
Environment="DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX=false"
Environment="DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SECCOMP=false"
Environment="DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=false"
EOF
```

Rootless 环境限制比较多, 已知限制包括但不限于

*   不能 `docker run --net=host`
*   WSL 下配置复杂

---

## 2. Nginx (编译安装)

~~可惜基于 [Pingora](https://github.com/cloudflare/pingora) 的 [River](https://github.com/memorysafety/river) 还没成熟, 否则我不会用 Nginx, 编译好麻烦, 还是 Rust 好…~~

为了最佳性能, 以及我们需要 brotli, 一般都编译安装 Nginx.

```sh
# 安装必要依赖
apt install -y build-essential cmake libpcre3 libpcre3-dev libpcre2-dev zlib1g-dev openssl libssl-dev libxml2-dev libxslt1-dev libgd-dev libgeoip-dev libgoogle-perftools-dev libperl-dev perl-base perl

# 使用 mimalloc, 性能更佳
apt install libmimalloc2.0
cd /usr/lib && ln ./x86_64-linux-gnu/libmimalloc.so.2.0 libmimalloc.so

# Nginx 版本, 目前为 1.27.4, 参见 https://freenginx.org/
export NGINX_VERSION="1.27.4"

# 新建编译用工作目录(大概率还没有)
mkdir /data
mkdir /data/compile
mkdir /data/compile/nginx

export COMPILE_PATH="/data/compile/nginx"

# 进入编译 Nginx 用的工作目录
cd $COMPILE_PATH

# 我们使用开源版本的 Nginx, 叫 freenginx.
wget https://freenginx.org/download/freenginx-$NGINX_VERSION.tar.gz
tar -zxvf freenginx-$NGINX_VERSION.tar.gz
rm freenginx-$NGINX_VERSION.tar.gz
mv freenginx-$NGINX_VERSION src

# 下载 Brotli
git clone https://github.com/google/ngx_brotli && cd ngx_brotli && git submodule update --init && cd -

# configure, 可以根据实际需要改动, 不过应该也不用
cd src
./configure \
--prefix=/etc/nginx \
--sbin-path=/usr/sbin/nginx \
--modules-path=/usr/lib/nginx/modules \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--pid-path=/var/run/nginx.pid \
--lock-path=/var/run/nginx.lock \
--http-client-body-temp-path=/var/cache/nginx/client_temp \
--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
--user=nginx \
--group=nginx \
--with-threads \
--with-file-aio \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_v3_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_xslt_module \
--with-http_image_filter_module \
--with-http_geoip_module \
--with-http_sub_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_mp4_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_auth_request_module \
--with-http_random_index_module \
--with-http_secure_link_module \
--with-http_degradation_module \
--with-http_slice_module \
--with-http_stub_status_module \
--with-http_perl_module \
--with-mail \
--with-mail_ssl_module \
--with-stream \
--with-stream_ssl_module \
--with-stream_realip_module \
--with-stream_geoip_module \
--with-stream_ssl_preread_module \
--add-module=$COMPILE_PATH/ngx_brotli \
--with-compat \
--with-cc-opt='-g0 -O3 -fstack-reuse=all -fdwarf2-cfi-asm -fplt -fno-trapv -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-stack-check -fno-stack-clash-protection -fno-stack-protector -fcf-protection=none -fno-split-stack -fno-sanitize=all -fno-instrument-functions'

# 编译, CPU 有几核就 -j 几
make -j2

# 安装到指定目录
make install

# 配置 systemd 持久化
cat <<'TEXT' > /etc/systemd/system/nginx.service
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking

Restart=always
RestartSec=15
StartLimitInterval=0

User=root

Environment="LD_PRELOAD=/usr/lib/libmimalloc.so"

ExecStartPre=/bin/rm -rf /dev/shm/nginx
ExecStartPre=/bin/mkdir /dev/shm/nginx
ExecStartPre=/bin/chmod 711 /dev/shm/nginx
ExecStartPre=/bin/mkdir /dev/shm/nginx/tcmalloc
ExecStartPre=/bin/chmod 0777 /dev/shm/nginx/tcmalloc
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s stop
ExecStopPost=/bin/rm -rf /dev/shm/nginx

PrivateTmp=true

[Install]
WantedBy=multi-user.target
TEXT

# 配置文件参考
# 备份一下, 养成习惯
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak

# 根据实际情况修改再执行!!!
cat <<'TEXT' > /etc/nginx/nginx.conf
# daemon off;
# pid /run/nginx/nginx.pid;
user nginx nginx;
worker_processes auto;
worker_cpu_affinity auto;
worker_priority -20;
worker_rlimit_nofile 51200;

events
{
    use epoll;
    worker_connections 10240;
    multi_accept on;
}

http
{
    include mime.types;
    # set_real_ip_from 0.0.0.0/0;
    # 有用 Cloudflare CDN, 解除注释下一行
    # real_ip_header CF-Connecting-IP;

    default_type  application/octet-stream;
    charset utf-8;

    http2 on;

    log_format details '[$time_local][$status]|[Client] "$remote_addr" |[Host] "$host" |[Refer] "$http_referer" |[UA] "$http_user_agent" |[REQ] "$request" |[CONNECT] "$connection_requests" |[TIME] "$request_time" |[LENGTH] "$bytes_sent" |[UPSTREAM] "$upstream_addr" |[U_HEAD_TIME] "$upstream_header_time" |[U_CON_TIME] "$upstream_connect_time" |[U_RSP_TIME] "$upstream_response_time" |[U_STATUS] "$upstream_status" |[U_LENGTH] "$upstream_response_length"';
    log_format details_pp '[$time_local][$status]|[Client] "$proxy_protocol_addr" |[Host] "$host" |[Refer] "$http_referer" |[UA] "$http_user_agent" |[REQ] "$request" |[CONNECT] "$connection_requests" |[TIME] "$request_time" |[LENGTH] "$bytes_sent" |[UPSTREAM] "$upstream_addr" |[U_HEAD_TIME] "$upstream_header_time" |[U_CON_TIME] "$upstream_connect_time" |[U_RSP_TIME] "$upstream_response_time" |[U_STATUS] "$upstream_status" |[U_LENGTH] "$upstream_response_length"';

    server_names_hash_bucket_size 512;
    client_header_buffer_size 32k;
    large_client_header_buffers 4 32k;
    client_max_body_size 50m;

    # Perf
    access_log off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    reset_timedout_connection on;
    client_body_timeout 10;
    send_timeout 2;
    keepalive_timeout 60;

    # SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_ecdh_curve X25519:P-256:P-384:P-224:P-521;
    ssl_dhparam /etc/nginx/certs/dhparam.pem;
    ssl_session_cache shared:MozSSL:30m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    # 境外机器, 修改 `223.5.5.5 223.6.6.6` 为 `1.1.1.1 1.0.0.1`
    resolver 223.5.5.5 223.6.6.6 valid=60s;
    resolver_timeout 2s;
    ssl_early_data on;
    proxy_set_header Early-Data $ssl_early_data;
    ssl_buffer_size 8k;

    ##
    # Connection header for WebSocket reverse proxy
    ##
    map $http_upgrade $connection_upgrade {
      default upgrade;
      '' close;
    }

    # fastcgi
    fastcgi_connect_timeout 300;
    fastcgi_send_timeout 300;
    fastcgi_read_timeout 300;
    fastcgi_buffer_size 64k;
    fastcgi_buffers 4 64k;
    fastcgi_busy_buffers_size 128k;
    fastcgi_temp_file_write_size 256k;
    fastcgi_intercept_errors on;

    # compress
    gzip on;
    gzip_min_length 1k;
    gzip_buffers 4 16k;
    gzip_http_version 1.1;
    gzip_comp_level 6;
    gzip_types
        # text/html
        text/css
        text/javascript
        text/xml
        text/plain
        text/x-component
        application/javascript
        application/x-javascript
        application/json
        application/xml
        application/rss+xml
        application/atom+xml
        font/truetype
        font/opentype
        application/vnd.ms-fontobject
        image/svg+xml;
    gzip_vary on;
    gzip_proxied expired no-cache no-store private auth;
    gzip_disable "MSIE [1-6]\.";
    brotli on;
    brotli_comp_level 6;
    brotli_types
        # text/html
        text/css
        text/javascript
        text/xml
        text/plain
        text/x-component
        application/javascript
        application/x-javascript
        application/json
        application/xml
        application/rss+xml
        application/atom+xml
        font/truetype
        font/opentype
        application/vnd.ms-fontobject
        image/svg+xml;

    # Others
    limit_conn_zone $binary_remote_addr zone=perip:10m;
    limit_conn_zone $server_name zone=perserver:10m;
    server_tokens off;

    # Nginx 对 QUIC 支持不佳, 我选择关掉, 如果你想试试, 下面四行解除注释.
    # http3 on;
    # http3_hq on;
    # quic_retry on;
    # add_header Alt-Svc 'h3=":443"; ma=86400';

    # Default HTTP server
    server
    {
        listen 80 default_server;
        listen [::]:80 default_server;

        # 防止被扫描器扫描
        location / {
            return 444;
        }

        access_log  /data/www/logs/nxdomain.com.log details;
    }

    # Default HTTPS server
    server
    {
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        # 监听 UDS, 某些情况下非常有用
        # listen unix:/dev/shm/nginx/default-ssl.sock ssl default_server;
        # Nginx 对 QUIC 支持不佳, 我选择关掉, 如果你想试试, 下面这行解除注释. 需要注意: reuseport 只能写一次
        # listen 443 quic reuseport;

        server_name _;
        # 关键: 拒绝未知的 SNI, 防止证书出卖源站
        ssl_reject_handshake on;

        location / {
            return 444;
        }

        access_log  /data/www/logs/nxdomain.com.log details;
    }

    # Include other conf
    include /etc/nginx/conf.d/*.conf;
}
TEXT

# 下面创建各种目录

mkdir /var/cache/nginx
# 配置文件
mkdir /etc/nginx/conf.d
# 证书
mkdir /etc/nginx/certs
# 网页文件
mkdir /data/www
# 访问日志
mkdir /data/www/logs
# 默认网页
mkdir /data/www/default

# 生成 dhparam
openssl dhparam -out /etc/nginx/certs/dhparam.pem 2048

# 添加用户, 设定文件权限
useradd -M -s /sbin/nologin nginx
chown -R nginx:nginx /data/www
chmod -R 700 /data/www
chown -R nginx:nginx /etc/nginx/certs
chmod -R 700 /etc/nginx/certs

# 启动 Nginx!
systemctl daemon-reload && systemctl enable --now nginx
```

配置文件保存在 `/etc/nginx/conf.d` 下, 证书保存在 `/etc/nginx/certs` 下, 访问日志位于 `/data/www/logs`.

### 2.1. 安全实践: **Nginx 暴露默认证书**

使用我的推荐配置, 或者你自己照葫芦画瓢, 配置默认 server 块, 然后设置 `ssl_reject_handshake on;` 就行 (新版本如此, 老版本略有差别, 自行搜索).

```conf
    server
    {
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;

        server_name _;
        # 关键: 拒绝未知的 SNI, 防止证书出卖源站
        ssl_reject_handshake on;

        location / {
            # 444 不是标准状态码, Nginx 的意思是直接切断连接, 省流量 (返回 403 还得点流量呢)
            return 444;
        }

        access_log  /data/www/logs/nxdomain.com.log details;
    }
```

### 2.2. 安全实践: TLS / HTTP2 指纹识别及风控

我没看到任何开箱即用的开源方案实际上. 遂想到 Nginx stream, 能根据 SNI 分流, 再让我自己写的玩意处理去.

但坑人的是, Nginx 并不会保留原 ClientHello 信息. 遂开发了 [simple-rproxy](https://github.com/hanyu-dev/simple-rproxy), 目前已在生产环境(?)中使用. 不过吧, no guarantee 就是, 欢迎佬友试用 :) 主打一个 Zero-copy 高性能.

~~这玩意还有个非常特殊的功能, 等我充分测试, 以后再慢慢说~~

### 2.3. `acme.sh` 获取 SSL 证书

~~推荐借助 cloudflared 实现不暴露服务器端口, 安全多了~~

(说实在的, 每台机器都得部署一次, 好麻烦, 我有写个 acme 客户端的想法, 获取一次证书再统一进行部署)

Let’s Encrypt 已经成为过去时, 让我们拥抱 ZeroSSL 的怀抱. 建议先前往 ZeroSSL 注册个账号 (假设是 `admin@example.com`).

#### 2.3.1. 安装

```sh
curl https://get.acme.sh | sh -s email=admin@example.com
acme.sh --upgrade --auto-upgrade
acme.sh --set-default-ca --server zerossl
acme.sh --register-account -m admin@example.com --server zerossl
```

#### 2.3.2. 获取证书

假设你的域名为 `example.com`, DNS 托管在华为云(唯一一个免费的支持分区域解析的), 使用 TXT 验证(不推荐文件验证, 尤其是前面我们已经屏蔽了不带域名的连接防止被扫描). 其他 DNS 托管商自行查看官方文档.

我们默认证书会存放在 `/etc/nginx/certs` 下.

```sh
# 子账号用户名, 需要自行去控制台添加
export HUAWEICLOUD_Username="***"
# 子账号程序访问安全密钥
export HUAWEICLOUD_Password="***"
# "我的凭证" 里面的帐号名
export HUAWEICLOUD_DomainName="***"

# 根据需要添加二级域名的泛域名即可, 尽量一次性想好, 便于管理
acme.sh --issue --dns dns_huaweicloud -d "example.com" -d "*.example.com" -d "*.api.example.com" -d "*.app.example.com"

mkdir /etc/nginx/certs/example.com

# 为了便于管理 acme.sh 获取到证书后的系列操作, 我们用一个单独的脚本.
cat <<'EOF' > /etc/nginx/certs/reload.sh
#!/bin/bash

# Nginx
systemctl force-reload nginx
EOF
chmod +x /etc/nginx/certs/reload.sh

# 等待签发就行, 然后安装证书. 应当注意要 force-reload
acme.sh --install-cert -d "example.com" -d "*.example.com" -d "*.api.example.com" -d "*.app.example.com" --fullchain-file /etc/nginx/certs/example.com/fullchain.pem --key-file /etc/nginx/certs/example.com/privkey.pem --reloadcmd "/etc/nginx/certs/reload.sh"
```

到此证书获取成功, 后面会自动续期.

*   证书文件: `/etc/nginx/certs/example.com/fullchain.pem`
*   私钥: `/etc/nginx/certs/example.com/privkey.pem`

> **如果你需要上传到 CDN, 这里分享一些脚本暂且用用.**
> 
> 举例脚本位于 `/etc/nginx/certs/aliyun_ssl.py`, `/etc/nginx/certs/reload.sh` 里面加一行 `python /etc/nginx/certs/aliyun_ssl.py >> "/etc/nginx/certs/aliyun_ssl.log" 2>&1` (现在知道为什么要单独一个 sh 作 reloadcmd 了吧), 就能实现自动刷新 CDN SSL 证书了.
> 
> *   阿里云 DCDN
> 
> ```py
> #!/usr/bin/env python
> # -*- coding: utf-8 -*-
> # author: 'cxw620'
> # time: 2023-10-03
> # 使用 ZeroSSL + acme.sh 方案
> # 使用前: pip install alibabacloud_dcdn20180115
> # 使用前: pip install alibabacloud_cas20200407
> 
> import os
> import sys
> 
> from typing import List
> from datetime import datetime
> 
> from alibabacloud_tea_openapi.client import Client as OpenApiClient
> from alibabacloud_tea_openapi import models as open_api_models
> from alibabacloud_tea_util import models as util_models
> from alibabacloud_openapi_util.client import Client as OpenApiUtilClient
> 
> 
> # 认证信息, 自行前往控制台获取
> AK = "{AK}"
> SK = "{SK}"
> DOMAIN_SSL = {
>     "example.com": {
>         "fullchain": "/etc/nginx/certs/example.com/fullchain.pem",
>         "privkey": "/etc/nginx/certs/example.com/privkey.pem",
>     },
> }
> 
> DOMAIN_DCDN = {
>     "example.com": [
>         "example1.example.com",
>         "example2.example.com",
>         "example3.example.com",
>     ],
> }
> 
> def create_client(
>     access_key_id: str,
>     access_key_secret: str,
> ) -> OpenApiClient:
>     """
>     使用AK&SK初始化账号Client
>     @param access_key_id:
>     @param access_key_secret:
>     @return: Client
>     @throws Exception
>     """
>     config = open_api_models.Config(
>         # 必填，您的 AccessKey ID,
>         access_key_id=access_key_id,
>         # 必填，您的 AccessKey Secret,
>         access_key_secret=access_key_secret
>     )
>     # Endpoint 请参考 https://api.aliyun.com/product/dcdn
>     config.endpoint = f'dcdn.aliyuncs.com'
>     return OpenApiClient(config)
> 
> @staticmethod
> def create_api_info() -> open_api_models.Params:
>     """
>     API 相关
>     @param path: params
>     @return: OpenApi.Params
>     """
>     params = open_api_models.Params(
>         # 接口名称,
>         action='BatchSetDcdnDomainCertificate',
>         # 接口版本,
>         version='2018-01-15',
>         # 接口协议,
>         protocol='HTTPS',
>         # 接口 HTTP 方法,
>         method='POST',
>         auth_type='AK',
>         style='RPC',
>         # 接口 PATH,
>         pathname=f'/',
>         # 接口请求体内容格式,
>         req_body_type='json',
>         # 接口响应体内容格式,
>         body_type='json'
>     )
>     return params
> 
> def update_ssl(ssl_domain: str, ssl_sub_domains: list[str]) -> bool:
>     def read_cert(ssl_domain: str):
>         print("Read Certs!")
>         with open(DOMAIN_SSL[ssl_domain]["fullchain"], "r") as cert:
>             cert_text = cert.read()
>         with open(DOMAIN_SSL[ssl_domain]["privkey"], "r") as key:
>             key_text = key.read()
>         return [cert_text, key_text]
>     cert_info = read_cert(ssl_domain)
>     client = create_client(AK, SK)
>     params = create_api_info()
>     # query params
>     queries = {}
>     queries['DomainName'] = ",".join(ssl_sub_domains)
>     queries['CertName'] = f"{ssl_domain} Updated At {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
>     queries['CertType'] = 'upload'
>     queries['SSLProtocol'] = 'on'
>     queries['SSLPub'] = cert_info[0]
>     queries['SSLPri'] = cert_info[1]
>     # runtime options
>     runtime = util_models.RuntimeOptions()
>     request = open_api_models.OpenApiRequest(
>         query=OpenApiUtilClient.query(queries)
>     )
> 
>     try:
>         print(client.call_api(params, request, runtime))
>         return True
>     except Exception as error:
>         print(f"设置属于[{ssl_domain}]的证书失败: {error}")
>         return False
> 
> if __name__ == '__main__':
>     for ssl_domain in DOMAIN_DCDN:
>         domain_list = DOMAIN_DCDN[ssl_domain]
>         print(f"开始设置属于[{ssl_domain}]的证书")
>         domain_chunks = [domain_list[i:i+10] for i in range(0, len(domain_list), 10)]
>         for i, chunk in enumerate(domain_chunks):
>             print(f"设置属于[{ssl_domain}]的证书 -> Chunk {i+1}")
>             resp = update_ssl(ssl_domain, chunk)
>             if resp:
>                 print(f"设置属于[{ssl_domain}]的证书成功")
> ```
> 
> *   腾讯云
> 
>     比较 tricky, 建议改改再用, 而且我现在不用腾讯云了, 腾讯云 ECDN 变成 EO 了, API 应该也有变, ~~毕竟腾讯云对待 SDK 的态度并不认真~~.
> 
> ```py
> #!/usr/bin/env python
> # -*- coding: utf-8 -*-
> # author: 'zfb, cxw620'
> # time: 2022-09-11 22:00
> # 使用前: pip install tencentcloud-sdk-python
> 
> import json
> from datetime import datetime
> from tencentcloud.common import credential
> from tencentcloud.common.profile.client_profile import ClientProfile
> from tencentcloud.common.profile.http_profile import HttpProfile
> from tencentcloud.common.exception.tencent_cloud_sdk_exception import (
>     TencentCloudSDKException,
> )
> from tencentcloud.ssl.v20191205 import ssl_client
> from tencentcloud.ssl.v20191205 import models as models_ssl
> from tencentcloud.ecdn.v20191012 import ecdn_client
> from tencentcloud.ecdn.v20191012 import models as models_ecdn
> from tencentcloud.cdn.v20180606 import cdn_client
> from tencentcloud.cdn.v20180606 import models as models_cdn
> 
> # ---------------Static--------------------------
> SECRETID = "***"
> SECRETKEY = "***"
> DOMAIN_PACK = {
>     "example.com": [
>         "example1.example.com",
>         "example2.example.com",
>         "example3.example.com",
>     ],
> }
> 
> LOC = "/root/.acme.sh/"
> # 控制功能开关
> # 是否开启HTTP2
> ENABLE_HTTP2 = True
> # 是否开启HSTS
> ENABLE_HSTS = True
> # 为HSTS设定最长过期时间（以秒为单位）
> HSTS_TIMEOUT_AGE = 3153600
> # HSTS包含子域名（仅对泛域名有效）
> HSTS_INCLUDE_SUBDOMAIN = True
> # 是否开启OCSP
> ENABLE_OCSP = True
> # 是否开启HTTP->HTTPS强制跳转
> FORCE_REDIRECT = True
> # TLS Version设置, 默认除了TLS1.0("TLSv1")全开
> TLS_VERSION = ["TLSv1.1", "TLSv1.2", "TLSv1.3"]
> # ---------------Static--------------------------
> 
> 
> def read_cert(_domain):
>     """读取证书内容"""
>     with open(LOC + _domain + "_ecc/" + "fullchain" + ".cer", "r") as _cer:
>         _cer_text = _cer.read()
>     with open(LOC + _domain + "_ecc/" + _domain + ".key", "r") as _key:
>         _key_text = _key.read()
>     timestr = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
>     _cert_full = {
>         "CertificatePublicKey": _cer_text,
>         "CertificatePrivateKey": _key_text,
>         "Alias": "Auto Upload at {}".format(timestr),
>     }
>     return _cert_full
> 
> 
> def upload_cert(_domain):
>     try:
>         cred = credential.Credential(SECRETID, SECRETKEY)
>         httpProfile = HttpProfile()
>         httpProfile.endpoint = "ssl.tencentcloudapi.com"
> 
>         clientProfile = ClientProfile()
>         clientProfile.httpProfile = httpProfile
>         client = ssl_client.SslClient(cred, "", clientProfile)
> 
>         req = models_ssl.UploadCertificateRequest()
>         params = read_cert(_domain)
>         req.from_json_string(json.dumps(params))
> 
>         resp = client.UploadCertificate(req)
>         print(resp.to_json_string())
>         return str(resp.CertificateId)
> 
>     except TencentCloudSDKException as err:
>         print(err)
>         return ""
> 
> 
> def update_cdn_ssl(_ssl_domain: str, _domain_list: list):
>     """该函数实现为CDN更新ssl证书的功能"""
>     _id = upload_cert(_ssl_domain)
> 
>     def get_cdn_detail_info(_domain):
>         try:
>             cred = credential.Credential(SECRETID, SECRETKEY)
>             httpProfile = HttpProfile()
>             httpProfile.endpoint = "cdn.tencentcloudapi.com"
> 
>             clientProfile = ClientProfile()
>             clientProfile.httpProfile = httpProfile
>             client = cdn_client.CdnClient(cred, "", clientProfile)
> 
>             req = models_cdn.DescribeDomainsConfigRequest()
>             params = {"Filters": [{"Name": "domain", "Value": [_domain[0]]}]}
>             req.from_json_string(json.dumps(params))
> 
>             resp = client.DescribeDomainsConfig(req)
>             return resp.Domains
>         except TencentCloudSDKException as err:
>             print(err)
>             return []
> 
>     for _domain in _domain_list:
>         cdns = get_cdn_detail_info(_domain)
>         https = None
>         for _cdn in cdns:
>             if _cdn.Domain == _domain:
>                 https = _cdn.Https
>                 break
>         print(https)
>         # generate_https(https)
>         try:
>             cred = credential.Credential(SECRETID, SECRETKEY)
>             httpProfile = HttpProfile()
>             httpProfile.endpoint = "cdn.tencentcloudapi.com"
> 
>             clientProfile = ClientProfile()
>             clientProfile.httpProfile = httpProfile
>             client = cdn_client.CdnClient(cred, "", clientProfile)
>             req = models_cdn.UpdateDomainConfigRequest()
>             # 必选参数
>             # Domain: String, 域名
>             # 部分可选参数
>             # Https: Https, Https 加速配置
>             # 该类型详见 https://cloud.tencent.com/document/api/228/30987#Https
>             timestr = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
>             params = {
>                 "Domain": _domain,
>                 "ForceRedirect": {
>                     "Switch": "off",
>                     "RedirectType": "https",
>                     "RedirectStatusCode": 301,
>                     "CarryHeaders": "on",
>                 },
>                 "Https": {
>                     "Switch": "on",
>                     "CertInfo": {
>                         "CertId": _id,
>                         "Message": "Auto Update at {}".format(timestr),
>                     },
>                 },
>             }
>             if ENABLE_HTTP2:
>                 params["Https"]["Http2"] = "on"
> 
>             if ENABLE_HSTS:
>                 params["Https"]["Hsts"] = {
>                     "Switch": "off",
>                     "MaxAge": 0,
>                     "IncludeSubDomains": "off",
>                 }
>                 params["Https"]["Hsts"]["Switch"] = "on"
>                 params["Https"]["TlsVersion"] = TLS_VERSION
>                 params["Https"]["Hsts"]["MaxAge"] = HSTS_TIMEOUT_AGE
>                 if HSTS_INCLUDE_SUBDOMAIN:
>                     params["Https"]["Hsts"]["IncludeSubDomains"] = "on"
> 
>             if ENABLE_OCSP:
>                 params["Https"]["OcspStapling"] = "on"
>             if FORCE_REDIRECT:
>                 params["ForceRedirect"]["Switch"] = "on"
>             req.from_json_string(json.dumps(params))
> 
>             resp = client.UpdateDomainConfig(req)
>             print(resp.to_json_string())
>             print("成功更新域名为{0}的CDN的ssl证书为{1}".format(_domain, _id))
> 
>         except TencentCloudSDKException as err:
>             print(err)
>             exit("为CDN设置SSL证书{}出错".format(_id))
> 
> 
> if __name__ == "__main__":
>     for _ssl_domain in DOMAIN_PACK:
>         _domain_list = DOMAIN_PACK[_ssl_domain]
>         update_cdn_ssl(_ssl_domain, _domain_list)
> ```
> 
> *   华为云
> 
> ```py
> #!/usr/bin/env python
> # -*- coding: utf-8 -*-
> # author: 'cxw620'
> # time: 2022-07-01 20:00
> # 使用前安装 pip install huaweicloudsdkcore
> # 使用前安装 pip install huaweicloudsdkcdn
> from huaweicloudsdkcore.auth.credentials import GlobalCredentials
> from huaweicloudsdkcdn.v1.region.cdn_region import CdnRegion
> from huaweicloudsdkcore.exceptions import exceptions
> from huaweicloudsdkcdn.v1 import *
> from datetime import datetime
> 
> AK = "***"
> SK = "***"
> DOMAIN_CDN = [
>     {
>         # domain
>         "domain": "example1.example.com",
>         # where stored pem cert
>         "fullchain": "/etc/nginx/certs/example.com/fullchain.pem",
>         # where stored pem key
>         "privkey": "/etc/nginx/certs/example.com/privkey.pem"
>     },
>     {
>         # domain
>         "domain": "example2.example.com",
>         # where stored pem cert
>         "fullchain": "/etc/nginx/certs/example.com/fullchain.pem",
>         # where stored pem key
>         "privkey": "/etc/nginx/certs/example.com/privkey.pem"
>     },
>     {
>         # domain
>         "domain": "example3.example.com",
>         # where stored pem cert
>         "fullchain": "/etc/nginx/certs/example.com/fullchain.pem",
>         # where stored pem key
>         "privkey": "/etc/nginx/certs/example.com/privkey.pem"
>     },
> ]
> def read_cert(_domainInfo):
>         print("Read Certs!")
>         with open(_domainInfo["fullchain"], 'r') as _cert:
>             _cert_text = _cert.read()
>         with open(_domainInfo["privkey"], 'r') as _key:
>             _key_text = _key.read()
>         return [_cert_text, _key_text]
> 
> if __name__ == "__main__":
>     # 实际上是可以同时多域名的, 懒得改了
>     for _domain in DOMAIN_CDN:
>         _cert_info = read_cert(_domain)
> 
>         credentials = GlobalCredentials(AK, SK) \
> 
>         client = CdnClient.new_builder() \
>             .with_credentials(credentials) \
>             .with_region(CdnRegion.value_of("cn-north-1")) \
>             .build()
>         try:
>             request = UpdateDomainMultiCertificatesRequest()
>             forceRedirectConfigForceRedirect = ForceRedirect(
>                 switch=1,
>                 redirect_type="https"
>             )
>             httpsUpdateDomainMultiCertificatesRequestBodyContent = UpdateDomainMultiCertificatesRequestBodyContent(
>                 domain_name=_domain['domain'],
>                 https_switch=1,
>                 access_origin_way=3,
>                 force_redirect_https=1,
>                 force_redirect_config=forceRedirectConfigForceRedirect,
>                 http2=1,
>                 cert_name="cert " + _domain['domain'] + " Add Time " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
>                 certificate=_cert_info[0],
>                 private_key=_cert_info[1]
>             )
>             request.body = UpdateDomainMultiCertificatesRequestBody(
>                 https=httpsUpdateDomainMultiCertificatesRequestBodyContent
>             )
>             response = client.update_domain_multi_certificates(request)
>             print(response)
>         except exceptions.ClientRequestException as e:
>             print(e.status_code)
>             print(e.request_id)
>             print(e.error_code)
>             print(e.error_msg)
> 
> ```
> 
> ---
> 
> 个人 Python 仅限会一点, 当时 AI 也不火, 简简单单的写的, 看看佬友们有没有更好的分享分享…

---

## 3. 虚拟内网: [Easytier](https://github.com/EasyTier/EasyTier)

为什么要虚拟内网? 原因很简单, 搭建非公开的服务, 如个人的 emby 媒体库服务只给认识的人用, 还有自己管理的服务器间通过 Socks5 等非加密代理协议访问对方, 使用虚拟内网服务器无需暴露相应端口, 大大降低安全风险. 好处多多可以说了. 使用虚拟内网后, 服务器只需要暴露虚拟内网相关特定端口, SSH 都不用暴露在公网, 除非虚拟内网程序本体出了致命零日漏洞, 否则安全的很.

当然, 多提一嘴, 由于国内 v4 普遍为 NAT4, P2P 不可能打洞, 导致客户端间互联只能中转, 速度可想而知. 同时, zerotier 等虚拟内网方案普遍走 UDP, 部分运营商对 UDP 的 QoS 相当严重, 或者服务器线路差, 虚拟内网连接质量也会很差, 所以也非万金油方案. 值得高兴的是, v6 的普及让 NAT4 的影响没那么大了, 只要双方有 v6, 轻松 P2P 直连. 这就是题外话了.

以往一直使用 Zerotier, 但苦于 UDP QoS, 网络不稳定. 后面 Github 给我推送每日项目, 意外发现了 Easytier, 支持 TCP 模式! ~~而且, Rust 写的! 我能自己根据需要改代码!!~~ 于是切换到 Easytier, 比较稳定, 没什么问题.

缺点是, 因为还比较新, GUI 啥的不完善, 得手搓配置文件. ~~欸巧了, 我就喜欢这个…~~

### 3.1. 安装

```sh
mkdir /opt/easytier
cd /opt/easytier

# Latest version: https://github.com/EasyTier/EasyTier/releases
# 个人用着 2.0.3, 能跑就不动了
export EASYTIER_VERSION="2.0.3"

wget https://github.com/EasyTier/EasyTier/releases/download/v$EASYTIER_VERSION/easytier-linux-x86_64-v$EASYTIER_VERSION.zip

# 中国大陆机器, 没配置代理的话, 也可以用 gh-proxy 代理下载
# wget https://gh-proxy.com/https://github.com/EasyTier/EasyTier/releases/download/v$EASYTIER_VERSION/easytier-linux-x86_64-v$EASYTIER_VERSION.zip

unzip easytier-linux-x86_64-v$EASYTIER_VERSION.zip && rm easytier-linux-x86_64-v$EASYTIER_VERSION.zip && mv ./easytier-linux-x86_64/* ./ && rm -r easytier-linux-x86_64

cat << 'EOF' > /etc/systemd/system/easytier.service
[Unit]
Description=EasyTier Service
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
ExecStart=/opt/easytier/easytier-core -c /opt/easytier/config.toml

[Install]
WantedBy=multi-user.target

EOF
```

### 3.2. 配置文件

需要注意, IP 是 CIDR 形式的, 如 IP 是 10.0.0.1, 网段 /16 的话就是 `10.0.0.1/16`.

似乎支持 DHCP, 但虚拟内网还是给机器固定 IP 比较好.

```sh
export INSTANCE_NAME="{机器代号}"
export HOST_NAME="easytier-{机器代号, 小写}"
export UUID="{uuid, 不能重复哦}"
export IP="{IP}"

cat << EOF > /opt/easytier/config.toml
instance_name = "$INSTANCE_NAME"
hostname = "$HOST_NAME"
instance_id = "$UUID"
ipv4 = "$IP"
dhcp = false
# 默认 rpc_portal 是 127.0.0.1:12588, 不喜欢可以改
# rpc_portal = "127.0.0.1:3260"
listeners = [
  "tcp://0.0.0.0:3261",
  "tcp://[::]:3261",
  "udp://0.0.0.0:3261",
  "udp://[::]:3261",
  "wg://0.0.0.0:3262",
  "wg://[::]:3262"
]
relay-network-whitelist = "Hantong-Easytier"

[network_identity]
network_name = "{网络名称}"
network_secret = "{网络密钥, 不要泄露!!}"

# 如果不希望借助公共服务器组网, 可以配置为自己 VPS 的 IP
# 有多个 IP 依葫芦画瓢就行
[[peer]]
uri = "tcp://{服务器 IP}:3261"
[[peer]]
uri = "udp://{服务器 IP}:3261"

[flags]
# Default transport protocol, 配置为 TCP, 延迟会高一点, 但稳定一点
default_protocol = "tcp"
# TUN Device Name
dev_name = "easytier-tun"
# Encryption support
enable_encryption = true
# IPv6 support
enable_ipv6 = true
# TUN MTU
mtu = 1380
# Mode Latency first
# 这里逻辑我没弄明白说实在的, 就算 default_protocol 设置为 tcp, 这里设置为 true
# 还是会走 UDP. 可能是 BUG 吧.
latency_first = false

[file_logger]
level = "error"
file = "easytier.log"
dir = "/opt/easytier"

[console_logger]
level = "debug"

EOF
```

### 3.3. 启动

```sh
# Firewall Management, 如果是安全组记得去开
ufw allow 3261
ufw allow 3262
ufw allow from {你的虚拟内网 CIDR, 本文例子是 10.0.0.0/16} to any

systemctl daemon-reload && systemctl enable easytier.service --now
```

可以执行 `./easytier-cli route` 看当前路由状态; `./easytier-cli peer` 看当前加入网络的 peer.
如果你改了 rpc_portal, 记得这里也要给个参数 `-p ***` 指定一下.

## 4. Cloudflared

Cloudflare 大善人为我们提供了 cloudflared 服务, 做到无需服务器暴露公网端口即可提供网络服务, 最大限度减少攻击面, 推荐使用.

### 4.1. 安装

参考: [https://pkg.cloudflare.com/index.html](https://pkg.cloudflare.com/index.html)

```sh
# Add cloudflare gpg key
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null

# Add this repo to your apt repositories
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | sudo tee /etc/apt/sources.list.d/cloudflared.list

# install cloudflared
sudo apt-get update && sudo apt-get install cloudflared
```

### 4.2. 使用

*   登录 [Zero Trust 控制台](https://one.dash.cloudflare.com)
*   打开 `网络` → `tunnel`
*   点击 “创建隧道” → “选择 Cloudflared”, 然后命名, 确认即可
*   点击 `Debian`, 复制 `如果您的计算机上已安装 cloudflared：` 下面的买了到目标机器上运行即可
*   点击 `← 返回到“隧道”`, 点击你刚才创建的隧道 (中途有提示就直接确认即可), 点击 “编辑”
    此处示例我并没有实际安装, 所以显示状态停用.

    添加公共主机名, 按你的需求编辑即可, 例如:
    (我的对外服务都是这么部署的)

    应当注意, 这里是有顺序的, 由上往下依次匹配. 没有匹配到就看 catch-all 规则

    这里的配置会自动生效.

### 4.3. 一些实践

*   如果你的服务器是 IPv6 only 的

    你需要编辑 `/etc/systemd/system/cloudflared.service`, `ExecStart` 一行改一下命令行参数, 如:

    `ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel --edge-ip-version 6 run --token ***`

    加上 `--edge-ip-version 6`, 别的不用动.

*   想连接自定义的 region?

    官方 cloudflared 没这功能, 我打算改改…

---

## 结语

让我们下期再见! (下一期得是 Lv.1 权限了可能? 也不一定有, 感觉偏题了)

---

*本文版权遵照 CC BY-NC-SA 协议开放, 转载请标注出处.*

*囿于自身水平, 本文所述可能并非最佳实践, 但均已经过我个人亲测. 也欢迎各位佬友补充修正, 共建这份指南!*

*2025年3月3日晚, 于北京.*
