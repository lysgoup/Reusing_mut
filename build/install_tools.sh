#!/bin/bash

# set -euxo pipefail

# #wllvm and gllvm
# pip install --upgrade pip==9.0.3
# pip install wllvm
# mkdir ${HOME}/go
# go get github.com/SRI-CSL/gllvm/cmd/...

set -euxo pipefail
# 최신 Go 설치
GO_VERSION=1.20.5
cd /tmp
wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
rm go${GO_VERSION}.linux-amd64.tar.gz
# PATH에 새 Go 추가
export PATH=/usr/local/go/bin:$PATH
# Install Python packages
pip install --upgrade pip==9.0.3
pip install wllvm
# Install gllvm (GOPATH 모드)
export GOPATH="/opt/go"
mkdir -p $GOPATH
export GO111MODULE=off
export PATH="$PATH:$GOPATH/bin"
go get github.com/SRI-CSL/gllvm/cmd/...