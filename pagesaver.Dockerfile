# monolith
FROM ubuntu:18.04 as monolith

RUN apt update && \
apt install -y rustc cargo libssl-dev pkg-config && \
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

RUN apt-get update && \
apt-get dist-upgrade -y && \
apt-get install -y \
    --no-install-recommends \
    bash \
    tree \
    curl \
    libssl-dev \
    python3-minimal \
    python3-pip \
    ffmpeg \
    && \
rm -rf /var/lib/apt/lists/* && \
pip3 install -U pip && \
pip install -U youtube-dl

RUN adduser \
    --system \
    --disabled-password \
    --group \
    --gecos "" \
    --home /app \
    app \
    && \
mkdir -p /app/data/ipfs && \
chown -R app:app /app

COPY --from=ipfs /usr/local/bin/ipfs /usr/local/bin
COPY --from=monolith /root/.cargo/bin/monolith  /usr/local/bin
COPY --from=golang /build/pagesaver  /usr/local/bin
COPY    static/  /app/static

USER app
WORKDIR /app

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
