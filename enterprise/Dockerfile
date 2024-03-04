FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y build-essential git cmake \
                       zlib1g-dev libevent-dev \
                       sudo \
                       lsof \
                       libelf-dev llvm \
                       clang libc6-dev-i386

RUN mkdir /src && \
    git init
WORKDIR /src

# Link asm/byteorder.h into eBPF
RUN ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm

RUN apt-get update && apt install -y libpcap-dev

RUN apt-get update && apt install -y linux-tools-$(uname -r)

RUN apt-get update && apt install -y linux-headers-$(uname -r)

RUN apt-get update && apt install -y linux-tools-common linux-tools-generic

RUN apt-get update && apt install -y tcpdump

RUN apt-get update && apt install -y iproute2

ENV NODE_VERSION=16.13.0
RUN apt install -y curl
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
ENV NVM_DIR=/root/.nvm
RUN . "$NVM_DIR/nvm.sh" && nvm install ${NODE_VERSION}
RUN . "$NVM_DIR/nvm.sh" && nvm use v${NODE_VERSION}
RUN . "$NVM_DIR/nvm.sh" && nvm alias default v${NODE_VERSION}
ENV PATH="/root/.nvm/versions/node/v${NODE_VERSION}/bin/:${PATH}"
RUN node --version
RUN npm --version

# Build libbpf as a static lib
RUN git clone https://github.com/cdabruno/StatTrek && \
    cd StatTrek/libbpf-bootstrap && \
    git submodule update --init --recursive

RUN cd StatTrek/libbpf-bootstrap/libbpf/src && \
    make BUILD_STATIC_ONLY=y && \
    make install BUILD_STATIC_ONLY=y LIBDIR=/usr/lib/x86_64-linux-gnu/

# Clones the linux kernel repo and use the atest linux kernel source BPF headers 
RUN git clone --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git && \
    cp linux/include/uapi/linux/bpf* /usr/include/linux/