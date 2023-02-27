FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential libbsd-dev libarchive-dev libz-dev libbz2-dev liblzma-dev libssl-dev automake pkg-config libtool clang

COPY . /repo
WORKDIR /repo
RUN ./configure
RUN make -j8
RUN  clang++ /repo/mayhem/fuzz_text_diff.cpp -fsanitize=fuzzer,address /repo/libpkg/libpkg_flat.a -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libbsd-dev libarchive-dev
COPY --from=builder /repo/src/pkg /
COPY --from=builder /fuzz /fuzz_text_diff
