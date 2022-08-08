FROM debian

RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install golang
RUN apt-get -y install manpages man-db
#usefull for testing, del later
RUN apt-get -y install netcat net-tools tcpdump python3

WORKDIR /code

ENTRYPOINT tail -f /dev/null