FROM debian:bullseye-slim

RUN apt-get update
RUN apt-get -y install golang libpcap-dev
#usefull for testing, del later
RUN apt-get -y install manpages man-db
RUN apt-get -y install netcat net-tools tcpdump python3 iputils-ping

WORKDIR /code

ENTRYPOINT tail -f /dev/null
