FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang

COPY . /repo
WORKDIR /repo/misc
RUN gcc -o jsoninfo jsoninfo.c /repo/src/yyjson.c -I/repo/src
RUN clang++ /repo/mayhem/fuzz_yyjson_read.cpp /repo/src/yyjson.c -I /repo/src -fsanitize=fuzzer,address -o /fuzz

FROM ubuntu:20.04 as package
COPY --from=builder /repo/misc/jsoninfo /
COPY --from=builder /fuzz /fuzz_yyjson_read
