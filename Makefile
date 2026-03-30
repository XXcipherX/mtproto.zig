.PHONY: build release run test clean fmt deploy

SERVER ?= 209.131.70.125
CONFIG ?= config.toml

build:
	zig build

release:
	zig build -Doptimize=ReleaseFast

run:
	zig build run -- $(CONFIG)

test:
	zig build test

fmt:
	zig fmt src/

clean:
	rm -rf .zig-cache zig-out

deploy:
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
	ssh root@$(SERVER) 'systemctl stop mtproto-proxy'
	scp zig-out/bin/mtproto-proxy root@$(SERVER):/opt/mtproto-proxy/
	ssh root@$(SERVER) 'systemctl start mtproto-proxy && systemctl status mtproto-proxy --no-pager'
