build-core:
	docker build -t jstubbs/cloudz3sec .

build-tests: build-core
	docker build -t jstubbs/cloudz3sec-tests -f Dockerfile-tests .

build-perf: build-tests
	docker build -t jstubbs/cloudz3sec-perf -f Dockerfile-perf .

build: build-core build-tests build-perf

test: build
	docker run --rm -it jstubbs/cloudz3sec-tests