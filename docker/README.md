docker for SIP Sysrepo plugin.

## build dockerfile

```
$ docker build -t sysrepo/sysrepo-netopeer2:iop -f Dockerfile .
$ docker build -t sysrepo/sysrepo-netopeer2:iop_devel -f Dockerfile.devel .
```

## build dockerfile without cache

```
$ docker build --no-cache -t sysrepo/sysrepo-netopeer2:iop -f Dockerfile .
$ docker build --no-cache -t sysrepo/sysrepo-netopeer2:iop_devel -f Dockerfile.devel .
```

## run dockerfile with supervisor

```
$ docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -i -t -v /opt/yang:/opt/fork --name iop -p 830:830 --rm sysrepo/sysrepo-netopeer2:iop
```

## run dockerfile without supervisor

```
$ docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -i -t -v /opt/yang:/opt/fork --name iop --rm sysrepo/sysrepo-netopeer2:iop bash
$ ubusd &
$ rpcd &
$ sysrepod
$ sysrepo-plugind
$ netopeer2-server
```
