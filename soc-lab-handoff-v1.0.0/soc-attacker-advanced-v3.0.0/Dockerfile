FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        dnsutils \
        iputils-ping \
        jq \
        netcat-openbsd \
        nmap \
        openssl \
        procps \
        python3 \
        tini \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 10001 -g nogroup soc

WORKDIR /opt/soc
COPY src/attackctl.py /opt/soc/attackctl.py
COPY wordlists/ /opt/soc/wordlists/
RUN chmod +x /opt/soc/attackctl.py \
    && ln -s /opt/soc/attackctl.py /usr/local/bin/attackctl

USER soc
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sleep", "infinity"]
