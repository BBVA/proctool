.PHONY: test

test: .python-deps
	make bin/proctool
	pipenv run pytest -vv

.python-deps: Pipfile Pipfile.lock
	pipenv sync
	touch .python-deps

bin/proctool: main.go
	go build -o bin/proctool main.go

