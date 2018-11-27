# Docker setup

## Build you Docker container

```
# copy config to your openwrt build
make defconfig
make -j4
cat bin/targets/x86/generic/openwrt-x86-generic-generic-rootfs.tar.gz | docker import - sysrepo/sysrepo-netopeer2:openwrt
```

You can also fetch the prebuild one.
```
docker pull sysrepo/sysrepo-netopeer2:openwrt
```

## Enable IPv6 in docker

You will need to edit daemon.json  and restart docker.

```
cat /etc/docker/daemon.json
{
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8::c008/125"
}
sudo systemctl restart docker
```

## Create Docker network

Use the network interface which is connected to the Pantera HGW.

```
docker network create -d macvlan \
    --subnet=192.168.1.0/24 --gateway=192.168.1.1 \
    --subnet=2003:1c09:24:4d00::/61 --gateway=2003:1c09:24:4d00::10 \
     -o parent="insert interface" \
     -o macvlan_mode=bridge macvlan216
```

## Run OpenWrt inside Docker

```
docker run --name x86 --net=macvlan216 --ip=192.168.1.10 -it --rm openwrt:x86 /bin/sh

/ # traceroute 192.168.1.1
traceroute to 192.168.1.1 (192.168.1.1), 30 hops max, 38 byte packets
 1  www.routerlogin.net (192.168.1.1)  110.559 ms  0.317 ms  0.219 ms
```
