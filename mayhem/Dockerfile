FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libbsd-dev libarchive-dev libz-dev libbz2-dev liblzma-dev libssl-dev automake pkg-config libtool

COPY . /repo
WORKDIR /repo
RUN ./configure
RUN make -j8

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libbsd-dev libarchive-dev
COPY --from=builder /repo/src/pkg /
