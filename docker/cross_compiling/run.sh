#!/usr/bin/env bash
set -e

if [ ! -d "x86_sysrepo" ]; then
    mkdir x86_sysrepo
    docker create -ti --name tmp_docker_image sysrepo/sysrepo-netopeer2:latest bash
    docker cp tmp_docker_image:/usr/local/bin x86_sysrepo
    docker cp tmp_docker_image:/usr/local/lib x86_sysrepo
    docker rm tmp_docker_image
fi

docker build -t sysrepo/cross -f Dockerfile.cross .

if [ -d "cross_sysrepo" ]; then
    rm -rf cross_sysrepo
fi

mkdir cross_sysrepo
docker create -ti --name cross_docker_image sysrepo/cross bash
sudo docker cp cross_docker_image:/opt/dev/root cross_sysrepo
docker rm cross_docker_image

docker run -v ${PWD}:/copy_dir -ti --rm sysrepo/sysrepo-netopeer2 bash /copy_dir/patchelf.sh
