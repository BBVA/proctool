.PHONY: test clean

CFLAGS=-static

test: .python-deps bin/proctool tests/fixtures/open-self-multiple-times
	pipenv run pytest -vvs

.python-deps: Pipfile Pipfile.lock
	pipenv sync
	touch .python-deps

bin/proctool: main.go biff.go
	go build -o bin/proctool

biff.go: src/biff blob2go.py
	python blob2go.py src/biff > biff.go

clean:
	rm -f bin/proctool src/biff biff.go tests/fixtures/open-self-multiple-times
