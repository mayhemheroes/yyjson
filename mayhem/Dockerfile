FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential

COPY . /repo
WORKDIR /repo/misc
RUN gcc -o jsoninfo jsoninfo.c /repo/src/yyjson.c -I/repo/src

FROM ubuntu:20.04 as package
COPY --from=builder /repo/misc/jsoninfo /
