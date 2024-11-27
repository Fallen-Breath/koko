## fallen's fork

与上游的差异：

- 实现简单的 ssh 服务器指纹验证功能（https://github.com/jumpserver/jumpserver/issues/11901 ）

Docker Hub 的 [fallenbreath/jumpserver-koko](https://hub.docker.com/r/fallenbreath/jumpserver-koko) 镜像（不保证更新）：

- `fallenbreath/jumpserver-koko:v4.4.1-ce`

镜像构建指令例子：

```bash
make docker IMAGE_TAG=v4.4.1-ce
docker push fallenbreath/jumpserver-koko:v4.4.1-ce
```


# KoKo

**English** · [简体中文](./README_zh-CN.md)

KoKo is a connector of JumpServer for secure connections using character protocols, supporting SSH, Telnet, Kubernetes, SFTP and database protocols

Koko is implemented using Golang and Vue, and the name comes from a Dota hero [Kunkka](https://www.dota2.com.cn/hero/kunkka)。

## Features


- SSH
- SFTP
- Web Terminal
- Web File Management


## Installation

1. Clone the project

```shell
git clone https://github.com/jumpserver/koko.git
```

2. Build the application

Build the application in the koko project.
```shell
make
```
> If the build is successful, the build folder will be automatically generated under the project, which contains compressed packages of various architectures of the current branch.

## Usage (for Linux amd64 server)

1. Copy the compressed package file to the corresponding server

```
Build the default compressed package through make, the file name is as follows:
koko-[branch name]-[commit]-linux-amd64.tar.gz
```

2. Unzip the compiled compressed package
```shell
tar xzvf koko-[branch name]-[commit]-linux-amd64.tar.gz
```

3. Create the file `config.yml`, refer to [config_example.yml](https://github.com/jumpserver/koko/blob/master/config_example.yml)
```shell
touch config.yml
```

4. run koko
```shell
cd koko-[branch name]-[commit]-linux-amd64

./koko
```


## Setup development environment

1. Run the backend server

```shell

$ cp config_example.yml config.yml # 1. Prepare the configuration file
$ vim config.yml  # 2. Modify the configuration file, edit the address and bootstrap key
CORE_HOST: http://127.0.0.1:8080
BOOTSTRAP_TOKEN: PleaseChangeMe <change to the same as core>

$ go run ./cmd/koko/ # 3. Run, running requires go if not, download and install from go.dev
```


2. Run the ui frontend

```shell
$ cd ui 
$ yarn install
$ npm run serve
```

## Docker
To build multi-platform images using Docker Buildx, you need to install Docker version 19.03 or higher and enable the Docker Buildx plugin.

```shell
make docker
```
