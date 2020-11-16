.PHONY: dataset

dataset: hello/hello.proctool.log st-0.8.4/st.proctool.log
	pipenv sync
	pipenv run ./proctool2neo4j.py hello/hello.proctool.log hello
	pipenv run ./proctool2neo4j.py st-0.8.4/st.proctool.log st

hello/hello.proctool.log:
	cd hello; proctool $$(which gcc) -o hello.exe hello.c 2> hello.proctool.log

st-0.8.4/st.proctool.log:
	wget -q -O - https://dl.suckless.org/st/st-0.8.4.tar.gz | tar -zvx
	cd st-0.8.4; proctool $$(which make) 2> st.proctool.log
