Sysrepo Python application.

## run in docker

```
$ docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -i -t -v /opt/yang:/opt/fork --name iop --rm sysrepo/sysrepo-netopeer2:iop bash
$ sysrepoctl -e ipv4-non-contiguous-netmasks -m ietf-ip
$ # clear previous ietf-interfaces data
$ python ./sr_uci.py
```
