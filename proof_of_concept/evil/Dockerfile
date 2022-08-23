FROM debian:bullseye-slim

COPY ./config/docker-entrypoint.sh /tmp/

WORKDIR /tmp/

RUN apt-get update \
    && apt-get install -y \
       tcpdump \
       dsniff \
       git \
       golang \
       make \
       iproute2 \
       libpcap-dev \
       libusb-1.0-0-dev \
       libnetfilter-queue-dev \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/bettercap/bettercap \
    && cd bettercap \
    && make \
    && mkdir -p /spoof/ \
    && mv ./bettercap /spoof/ \
    && chmod +x /tmp/docker-entrypoint.sh

WORKDIR /spoof/

COPY ./config/bc-instr .

RUN rm -rf /tmp/bettercap/*

CMD /tmp/docker-entrypoint.sh
