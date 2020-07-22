.PHONY: test

test:
	make bin/proctool
	pipenv sync
	pipenv run pytest -vv

bin/proctool: main.go
	go build -o bin/proctool main.go

