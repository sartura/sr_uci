Cross compile sysrepo/netopeer2-server to any target from dockcross

# dockerfile base

The docker as base uses `dockcross/linux-armv7`, they support multiple platforms and the this build supports Linux based toolchains.
In case of using mips edit `linux-armv4` in openssl with the appropriate target.

# build

```
$ ./run.sh
```

# install

Copy archive cross_sysrepo/root.tar to the device and extract it in /opt/root, the path is harde coded.
Export the new path and run sysrepo.

```
$ export PATH="/opt/root/bin:$PATH"
$ sysrepoct -l
```
