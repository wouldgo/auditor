SHELL := /bin/sh
OUT := $(shell pwd)/_out
LIBPCAP := 1.10.1
BUILDARCH := $(shell uname -m)
GCC := $(OUT)/$(BUILDARCH)-linux-musl-cross/bin/$(BUILDARCH)-linux-musl-gcc
LD := $(OUT)/$(BUILDARCH)-linux-musl-cross/bin/$(BUILDARCH)-linux-musl-ld
VERSION := 2.0.12
GO_VERSION := $(shell go version  | grep --colour=never -oE '[[:digit:]]+.[[:digit:]]+' | head -n 1)

print:
	echo $(GO_VERSION)

clean-compile-auditor:     clean musl         deps compile-auditor
clean-compile-sni-catcher: clean musl libpcap deps compile-sni-catcher
docker-build:              docker-build-auditor    docker-build-sni-catcher

docker-build-auditor:
	./tools/docker-buildx \
		build \
			--platform linux/arm64 \
			-f cmd/auditor/Dockerfile \
			-t ghcr.io/wouldgo/auditor:$(VERSION) .

docker-build-sni-catcher:
	./tools/docker-buildx \
		build \
			--platform linux/arm64 \
			-f cmd/sni-catcher/Dockerfile \
			-t ghcr.io/wouldgo/sni-catcher:$(VERSION) .

auditor: deps #env
	DATABASE_FILE=$(OUT) \
	go run cmd/auditor/*.go

sni-catcher: deps #env
	CGO_CPPFLAGS="-I$(OUT)/libpcap-$(BUILDARCH)-linux-gnu/include" \
	CGO_LDFLAGS="-L$(OUT)/libpcap-$(BUILDARCH)-linux-gnu/lib" \
	CGO_ENABLED=1 \
	CC_FOR_TARGET=$(GCC) \
	CC=$(GCC) \
	go build \
		-ldflags '-linkmode external -extldflags -static' \
		-gcflags="all=-N -l" \
		-a -o _out/sni-catcher cmd/sni-catcher/*.go && \
	sudo --preserve-env ./_out/sni-catcher --database-file=$(OUT)

sni-catcher-debug: deps #env
	CGO_CPPFLAGS="-I$(OUT)/libpcap-$(BUILDARCH)-linux-gnu/include" \
	CGO_LDFLAGS="-L$(OUT)/libpcap-$(BUILDARCH)-linux-gnu/lib" \
	CGO_ENABLED=1 \
	CC_FOR_TARGET=$(GCC) \
	CC=$(GCC) \
	go build \
		-ldflags '-linkmode external -extldflags -static' \
		-gcflags="all=-N -l" \
		-a -o _out/sni-catcher cmd/sni-catcher/*.go && \
	DATABASE_FILE=$(OUT) sudo --preserve-env $(GVM_ROOT)/pkgsets/go$(GO_VERSION)/global/bin/dlv \
		--listen=:2345 \
		--headless=true \
		--api-version=2 \
			exec ./_out/sni-catcher

compile-sni-catcher:
	CGO_CPPFLAGS="-I$(OUT)/libpcap-$(BUILDARCH)-linux-gnu/include" \
	CGO_LDFLAGS="-L$(OUT)/libpcap-$(BUILDARCH)-linux-gnu/lib" \
	CGO_ENABLED=1 \
	CC_FOR_TARGET=$(GCC) \
	CC=$(GCC) \
	go build \
		-ldflags '-linkmode external -extldflags -static' \
		-a -o _out/sni-catcher cmd/sni-catcher/*.go

compile-auditor:
	CGO_ENABLED=0 \
	go build \
		-a -o _out/auditor cmd/auditor/*.go

#env:
#	$(eval export $(shell sed -ne 's/ *#.*$$//; /./ s/=.*$$// p' LOCAL_ENV))

deps: musl libpcap
	go mod tidy -v
	go mod download

musl:
	if [ ! -d "$(OUT)/$(BUILDARCH)-linux-musl-cross" ]; then \
		(cd $(OUT); curl -LOk https://musl.cc/$(BUILDARCH)-linux-musl-cross.tgz) && \
		tar zxf $(OUT)/$(BUILDARCH)-linux-musl-cross.tgz -C $(OUT); \
	fi

libpcap:
	if [ ! -d "$(OUT)/libpcap-libpcap-$(LIBPCAP)" ]; then \
		sudo apt install -y flex bison || echo "Your system does not have apt installed. Now it's your risk."; \
		(cd $(OUT); curl -LOk https://github.com/the-tcpdump-group/libpcap/archive/libpcap-$(LIBPCAP).tar.gz) && \
		tar zxf $(OUT)/libpcap-$(LIBPCAP).tar.gz -C $(OUT) && \
		cd $(OUT)/libpcap-libpcap-$(LIBPCAP) && \
		LD=$(LD) CC=$(GCC) ./configure --prefix=$(OUT)/libpcap-$(BUILDARCH)-linux-gnu LDFLAGS="-static" && \
		$(MAKE) && \
		$(MAKE) install; \
	fi

clean:
	sudo rm -Rf $(OUT) $(BINARY_NAME)
	mkdir -p $(OUT)
	touch $(OUT)/.keep
