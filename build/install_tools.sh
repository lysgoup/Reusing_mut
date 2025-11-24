#!/bin/bash

set -euxo pipefail

#wllvm and gllvm
pip install --upgrade pip==9.0.3
pip install wllvm

# GOPATH 구조에 맞게 gllvm 설치
mkdir -p ${GOPATH}/src/github.com/SRI-CSL
cd ${GOPATH}/src/github.com/SRI-CSL
git clone https://github.com/SRI-CSL/gllvm.git
cd gllvm
git checkout v1.2.8
go install ./cmd/...


