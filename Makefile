.PHONY: test clean

CFLAGS=-static

test: .python-deps bin/proctool bin/biff tests/fixtures/open-self-multiple-times
	pipenv run pytest -vvs

.python-deps: Pipfile Pipfile.lock
	pipenv sync
	touch .python-deps

bin/proctool: main.go
	go build -o bin/proctool main.go

bin/biff: biff
	mv biff bin/

clean:
	rm -f bin/proctool bin/biff tests/fixtures/open-self-multiple-times
