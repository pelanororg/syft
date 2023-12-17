BIN=./bin

all: build verify

tools:
	# for selfrando...
	#docker buildx build --platform linux/amd64 -t localhost/tools:latest .
	docker build -t localhost/tools:latest .

build: clean tools
	docker run -it -v $(shell pwd):/mount -w /mount/project localhost/tools:latest make

verify: tools
	docker run -it -v $(shell pwd):/mount -w /mount/project localhost/tools:latest make verify | tee actual_verify
	diff -u expected_verify actual_verify

debug:
	docker run -it --rm -v $(shell pwd):/mount -w /mount/project localhost/tools:latest bash

clean:
	rm -f $(BIN)/*

.PHONY: build-canary clean
