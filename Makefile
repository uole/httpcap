GOPATH:=$(shell go env GOPATH)
VERSION:="0.0.1"
DATETIME:=$(shell date)
GITVERSION:=$(shell git rev-parse --short HEAD)


.PHONY: build
build:
	go mod vendor
	go build -ldflags "-s -w -X 'github.com/uole/httpcap/version.Version=$(VERSION)' -X 'github.com/uole/httpcap/version.GitVersion=$(GITVERSION)' -X 'github.com/uole/httpcap/version.BuildDate=$(DATETIME)'" -o ./bin/httpcap ./cmd/main.go
