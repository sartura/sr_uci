#!/usr/bin/env bash

cd /opt/dev
mkdir root

# copy
cp -r ${CROSS_ROOT}/bin root
cp -r ${CROSS_ROOT}/lib root
cp -r ${CROSS_ROOT}/${CROSS_TRIPLE}/sysroot/lib/* root/lib/
cp -r ${CROSS_ROOT}/etc/ root
cp -r /opt/root/etc/sysrepo root/etc/
cp -r ${CROSS_ROOT}/etc/keystored root/etc

# clean
rm -rf root/bin/${CROSS_TRIPLE}*
rm -rf root/lib/lib${CROSS_TRIPLE}*
rm -rf root/lib/pkgconfig
rm -rf root/lib/cmake
rm -rf root/lib/engines
rm -rf root/lib/gcc
rm -rf root/lib/ldscripts
