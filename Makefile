SHELL := bash

ROOTDIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
GOPATH ?= $(shell go env GOPATH)
GO ?= go

IMAGE_TAG = garm-provider-azure-build

USER_ID=$(shell ((docker --version | grep -q podman) && echo "0" || id -u))
USER_GROUP=$(shell ((docker --version | grep -q podman) && echo "0" || id -g))
GARM_PROVIDER_NAME := "garm-provider-azure"

default: build

.PHONY : build build-static test install-lint-deps lint go-test fmt fmtcheck verify-vendor verify create-release-files release

build:
	@$(GO) build .

clean: ## Clean up build artifacts
	@rm -rf ./bin ./build ./release

build-static:
	@echo Building
	docker build --tag $(IMAGE_TAG) .
	mkdir -p build
	docker run --rm -e USER_ID=$(USER_ID) -e USER_GROUP=$(USER_GROUP) -v $(PWD)/build:/build/output:z -v $(PWD):/build/garm-provider-azure:z $(IMAGE_TAG) /build-static.sh
	@echo Binaries are available in $(PWD)/build

test: verify go-test

install-lint-deps:
	@$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

lint:
	@golangci-lint run --timeout=8m --build-tags testing

go-test:
	@$(GO) test -race -mod=vendor -tags testing -v $(TEST_ARGS) -timeout=15m -parallel=4 -count=1 ./...

fmt:
	@$(GO) fmt $$(go list ./...)

fmtcheck:
	@gofmt -l -s $$(go list ./... | sed -n 's/github.com\/cloudbase\/garm-provider-azure\/\(.*\)/\1/p') | grep ".*\.go"; if [ "$$?" -eq 0 ]; then echo "gofmt check failed; please tun gofmt -w -s"; exit 1;fi

verify-vendor: ## verify if all the go.mod/go.sum files are up-to-date
	$(eval TMPDIR := $(shell mktemp -d))
	@cp -R ${ROOTDIR} ${TMPDIR}
	@(cd ${TMPDIR}/garm-provider-azure && ${GO} mod tidy)
	@diff -r -u -q ${ROOTDIR} ${TMPDIR}/garm-provider-azure >/dev/null 2>&1; if [ "$$?" -ne 0 ];then echo "please run: go mod tidy && go mod vendor"; exit 1; fi
	@rm -rf ${TMPDIR}

verify: verify-vendor lint fmtcheck

##@ Release
create-release-files:
	./scripts/make-release.sh

release: build-static create-release-files ## Create a release
