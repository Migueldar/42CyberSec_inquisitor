FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install ettercap-common
RUN apt-get -y install manpages man-db

ENTRYPOINT tail -f /dev/null