Sysrepo Lua application.

## run in docker

```
$ docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -i -t -v /opt/yang:/opt/fork --name iop --rm sysrepo/sysrepo-netopeer2:iop bash
$ sysrepoctl -e ipv4-non-contiguous-netmasks -m ietf-ip
$ lua ./sr_uci.lua
```
