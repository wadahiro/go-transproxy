#!/bin/sh

VERSION=0.4

DIR=$(cd $(dirname $0); pwd)
cd $DIR

rm -rf bin/*
go build -v -o bin/transproxy -a -tags netgo -installsuffix netgo cmd/transproxy/main.go

tar cvzf go-transproxy-$VERSION.tar.gz bin README.md LICENSE

