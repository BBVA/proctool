.PHONY: test clean

CFLAGS=-static
CC=musl-gcc

test: bin/proctool tests/fixtures/open-self-multiple-times tests/fixtures/openat-self-multiple-times
	pytest -vvs

bin/proctool: main.go biff.go
	go build -o bin/proctool -ldflags="-linkmode external -extldflags=-static"

biff.go: src/biff blob2go.py
	python blob2go.py src/biff > biff.go

clean:
	rm -f bin/proctool src/biff biff.go tests/fixtures/open-self-multiple-times

install: bin/proctool
	sudo install bin/proctool /usr/local/bin
