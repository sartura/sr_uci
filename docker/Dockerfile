FROM ubuntu:18.04

MAINTAINER mislav.novakovic@sartura.hr

RUN \
      apt-get update && apt-get install -y \
      # general tools
      git \
      cmake \
      build-essential \
      vim \
      supervisor \
      # libyang
      libpcre3-dev \
      pkg-config \
      # sysrepo
      libavl-dev \
      libev-dev \
      libprotobuf-c-dev \
      protobuf-c-compiler \
      # netopeer2 \
      libssh-dev \
      libssl-dev \
      # bindings
      swig \
      python-dev

# add netconf user
RUN \
      adduser --system netconf && \
      echo "netconf:netconf" | chpasswd && \
      echo "root:root" | chpasswd

# generate ssh keys for netconf user
RUN \
      mkdir -p /home/netconf/.ssh && \
      ssh-keygen -A && \
      ssh-keygen -t dsa -P '' -f /home/netconf/.ssh/id_dsa && \
      cat /home/netconf/.ssh/id_dsa.pub > /home/netconf/.ssh/authorized_keys

# use /opt/dev as working directory
RUN mkdir /opt/dev
WORKDIR /opt/dev

# libyang
RUN \
      git clone https://github.com/CESNET/libyang.git && \
      cd libyang && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

# libredblack
RUN \
      git clone https://github.com/sysrepo/libredblack.git && \
      cd libredblack && \
      ./configure --prefix=/usr && \
      make && \
      make install && \
      ldconfig

# sysrepo
RUN \
      git clone https://github.com/sysrepo/sysrepo.git && \
      cd sysrepo && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_TESTS=OFF -DREPOSITORY_LOC:PATH=/etc/sysrepo -DUSE_AVL_LIB:BOOL=FALSE  .. && \
      make -j2 && \
      make install && \
      ldconfig

# libssh
RUN \
      git clone http://git.libssh.org/projects/libssh.git && \
      cd libssh && git checkout -b libssh-0.7.5 && mkdir build && cd build && \
      cmake .. && \
      make -j2 && \
      make install && \
      ldconfig

# libnetconf2
RUN \
      git clone https://github.com/CESNET/libnetconf2.git && \
      cd libnetconf2 && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" -DENABLE_BUILD_TESTS=OFF .. && \
      make -j2 && \
      make install && \
      ldconfig

# keystore
RUN \
      cd /opt/dev && \
      git clone https://github.com/CESNET/Netopeer2.git && \
      cd Netopeer2 && \
      cd keystored && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install && \
      ldconfig

# netopeer2
RUN \
      cd /opt/dev && \
      cd Netopeer2/server && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install && \
      cd ../../cli && mkdir build && cd build && \
      cmake -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install

# install python2 sysrepo language bindings
RUN apt-get install -y python-dev
RUN \
      cd /opt/dev/sysrepo/build && \
      make clean && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr -DGEN_PYTHON_VERSION=2 .. && \
      make -j2 && \
      make install

# debug tools
RUN \
      apt-get update && apt-get install -y \
      valgrind \
      gdb

# dependent libraries
RUN \
       apt-get update && apt-get install -y \
       libjson-c-dev \
       lua5.1-dev \
       lua5.1 \
       libcurl4-openssl-dev

# ubox
RUN \
      cd /opt/dev && \
      git clone  git://git.openwrt.org/project/libubox.git && \
      cd libubox && mkdir build && cd build && \
      git checkout fd57eea9f37e447814afbf934db626288aac23c4 && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" .. && \
      make -j2 && \
      make install

# uci
RUN \
      cd /opt/dev && \
      git clone git://nbd.name/uci.git && \
      cd uci && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=ON . && \
      make -j2 && \
      make install

# ubus
RUN \
      cd /opt/dev && \
      git clone https://git.openwrt.org/project/ubus.git && \
      cd ubus && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DBUILD_LUA=ON -DBUILD_EXAMPLES=OFF . && \
      make -j2 && \
      make install

# rpcd
RUN \
      cd /opt/dev && \
      git clone https://git.openwrt.org/project/rpcd.git && \
      cd rpcd && \
      cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE:String="Release" -DIWINFO_SUPPORT=NO . && \
      make -j2 && \
      make install && \
      mkdir /usr/lib/rpcd && \
      cp file.so /usr/lib/rpcd

# sr_uci
RUN \
      cd /opt/dev && \
      git clone https://github.com/sartura/sr_uci.git && \
      cd sr_uci && mkdir build && cd build && \
      git checkout master && \
      cmake .. && \
      make -j2 && \
      make install

# dhcp plugin
RUN \
      cd /opt/dev && \
      git clone https://github.com/sartura/dhcp.git && \
      cd dhcp && mkdir build && cd build && \
      git checkout master && \
      cmake -DPLUGIN=ON .. && \
      make -j2 && \
      cp lib/sysrepo-plugin-dt-* /usr/local/lib/sysrepo/plugins/ && \
      sysrepoctl -i -g ../yang/terastream-dhcp@2017-12-07.yang

COPY uci/dhcp /etc/config/dhcp

COPY uci/network /etc/config/network

COPY ubus/ubus.dhcp /usr/libexec/rpcd/dhcp
RUN chmod +x /usr/libexec/rpcd/dhcp

COPY ubus/ubus.router.network /usr/libexec/rpcd/router.network
RUN chmod +x /usr/libexec/rpcd/router.network

RUN echo '#!/bin/sh' > /etc/init.d/network && chmod +x /etc/init.d/network
RUN echo '#!/bin/sh' > /etc/init.d/odhcpd && chmod +x /etc/init.d/odhcpd


# provisioning plugin
RUN \
      cd /opt/dev && \
      git clone https://github.com/sartura/provisioning-plugin.git && \
      cd provisioning-plugin && mkdir build && cd build && \
      git checkout master && \
      cmake -DPLUGIN=ON .. && \
      make -j2 && \
      cp lib/sysrepo-plugin-dt-* /usr/local/lib/sysrepo/plugins/ && \
      sysrepoctl -i -g ../yang/terastream-provisioning@2018-05-14.yang

COPY ubus/router.system /usr/libexec/rpcd/router.system
RUN chmod +x /usr/libexec/rpcd/router.system

COPY ubus/system /usr/libexec/rpcd/system
RUN chmod +x /usr/libexec/rpcd/system


# network plugin
# remove default configuration from sysrepo
RUN \
      rm /etc/sysrepo/data/ietf-interfaces.startup && \
      touch /etc/sysrepo/data/ietf-interfaces.startup
RUN \
      cd /opt/dev && \
      git clone https://github.com/sartura/network-plugin.git && \
      cd network-plugin && mkdir build && cd build && \
      git checkout master && \
      cmake -DPLUGIN=ON .. && \
      make -j2 && \
      cp lib/sysrepo-plugin-dt-* /usr/local/lib/sysrepo/plugins/ && \
      sysrepoctl -i -g ../yang/terastream-interfaces-opto@2017-09-27.yang

COPY uci/network /etc/config/network

RUN echo '#!/bin/sh' > /etc/init.d/network
RUN chmod +x /etc/init.d/network

COPY ubus/network.device /usr/libexec/rpcd/network.device
RUN chmod +x /usr/libexec/rpcd/network.device

COPY ubus/router.net /usr/libexec/rpcd/router.net
RUN chmod +x /usr/libexec/rpcd/router.net

COPY ubus/sfp.ddm /usr/libexec/rpcd/sfp.ddm
RUN chmod +x /usr/libexec/rpcd/sfp.ddm


# firmware plugin
RUN \
      cd /opt/dev && \
      git clone https://github.com/sartura/firmware-plugin.git && \
      cd firmware-plugin && mkdir build && cd build && \
      git checkout master && \
      cmake -DPLUGIN=ON .. && \
      make -j2 && \
      cp lib/sysrepo-plugin-dt-* /usr/local/lib/sysrepo/plugins/ && \
      sysrepoctl -i -g ../yang/terastream-software@2017-11-01.yang -s /etc/sysrepo/yang && \
      sysrepoctl -e software-credentials-password -m terastream-software

# ubus call juci.system
COPY ubus/juci.system /usr/libexec/rpcd/juci.system
RUN chmod +x /usr/libexec/rpcd/juci.system

# ubus call juci.sysupgrade
COPY ubus/juci.sysupgrade /usr/libexec/rpcd/juci.sysupgrade
RUN chmod +x /usr/libexec/rpcd/juci.sysupgrade

# ubus call router.system
COPY ubus/router.system /usr/libexec/rpcd/router.system
run chmod +x /usr/libexec/rpcd/router.system


# sip plugin
RUN \
      cd /opt/dev && \
      git clone https://github.com/sartura/sip-plugin.git && \
      cd sip-plugin && mkdir build && cd build && \
      cmake -DPLUGIN=ON .. && \
      make -j2 && \
      cp lib/sysrepo-plugin-dt-* /usr/local/lib/sysrepo/plugins/ && \
      sysrepoctl -i -g ../yang/terastream-sip@2017-08-09.yang

COPY uci/voice_client /etc/config/voice_client

COPY ubus/asterisk.sip /usr/libexec/rpcd/asterisk.sip

RUN chmod +x /usr/libexec/rpcd/asterisk.sip

RUN echo '#!/bin/sh' > /etc/init.d/voice_client && chmod +x /etc/init.d/voice_client

RUN echo '#!/bin/sh' > /etc/init.d/asterisk && chmod +x /etc/init.d/asterisk


# wireless plugin
RUN \
      cd /opt/dev && \
      git clone https://github.com/sartura/wireless-plugin.git && \
      cd wireless-plugin && mkdir build && cd build && \
      git checkout master && \
      cmake -DPLUGIN=ON .. && \
      make -j2 && \
      cp lib/sysrepo-plugin-dt-* /usr/local/lib/sysrepo/plugins/ && \
      sysrepoctl -i -g ../yang/terastream-wireless@2017-08-08.yang

COPY uci/wireless /etc/config/wireless
RUN echo '#!/bin/sh' > /etc/init.d/network
RUN chmod +x /etc/init.d/network

COPY ubus/router.wireless /usr/libexec/rpcd/router.wireless
RUN chmod +x /usr/libexec/rpcd/router.wireless

COPY ubus/network.device /usr/libexec/rpcd/network.device
RUN chmod +x /usr/libexec/rpcd/network.device

# test plugin
RUN \
      cd /opt/dev && \
      git clone https://github.com/sartura/test-plugin.git && \
      cd test-plugin && mkdir build && cd build && \
      git checkout master && \
      cmake -DPLUGIN=ON .. && \
      make -j2 && \
      cp sysrepo-plugin-dt-* /usr/local/lib/sysrepo/plugins/ && \
      ls ../yang && \
      sysrepoctl -i -g ../yang/test-plugin@2018-02-20.yang

ENV EDITOR vim
EXPOSE 830

COPY supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
