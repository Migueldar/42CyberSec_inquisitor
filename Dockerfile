FROM debian

RUN apt-get update
RUN apt-get -y install golang
RUN apt-get -y install manpages man-db
#usefull for testing, del later
RUN apt-get -y install netcat net-tools tcpdump python3 iputils-ping

WORKDIR /code

ENTRYPOINT tail -f /dev/null