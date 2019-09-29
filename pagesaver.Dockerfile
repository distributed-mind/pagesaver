# monolith
FROM ubuntu:18.04 as monolith

RUN apt update &&\
apt install -y rustc cargo libssl-dev pkg-config &&\
cargo install --git https://github.com/Y2Z/monolith

# golang
FROM golang:latest as golang
WORKDIR /build

ADD . /build
RUN go build -a -o /build/pagesaver .

# ipfs
FROM ipfs/go-ipfs:latest as ipfs

# pagesaver
FROM ubuntu:18.04
WORKDIR /usr/src/app/

RUN apt-get update && \
apt-get dist-upgrade -y && \
apt-get install -y \
    bash \
    tree \
    curl \
    libssl-dev \
    && \
rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/src/app/data/ipfs &&\
mkdir -p /usr/src/app/data/monolith

COPY --from=golang /build/pagesaver  /usr/local/bin
COPY --from=ipfs /usr/local/bin/ipfs /usr/local/bin
COPY --from=monolith /root/.cargo/bin/monolith  /usr/local/bin
COPY    static/  /usr/src/app/static

# run pagesaver
EXPOSE 8000
# ipfs Swarm TCP; should be exposed to the public
EXPOSE 4001
# ipfs Daemon API; must not be exposed publicly but to client services under you control
EXPOSE 5001
# ipfs Web Gateway; can be exposed publicly with a proxy, e.g. as https://ipfs.example.org
EXPOSE 8080
# ipfs Swarm Websockets; must be exposed publicly when the node is listening using the websocket transport (/ipX/.../tcp/8081/ws).
EXPOSE 8081

ENTRYPOINT ["/bin/bash", "-c", "echo -n 'User: ' ; whoami ; echo -n 'Current Directory: ' ; pwd ; tree ; exec /usr/local/bin/pagesaver"]
