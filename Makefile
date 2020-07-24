.PHONY: test

test: .python-deps bin/proctool bin/biff
	pipenv run pytest -vv

.python-deps: Pipfile Pipfile.lock
	pipenv sync
	touch .python-deps

bin/proctool: main.go
	go build -o bin/proctool main.go

bin/biff:
	gcc -static -o bin/biff biff.c 
