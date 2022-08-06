FROM kalilinux/kali-rolling:latest

#RUN apt-get update 
#&& apt-get upgrade
#RUN apt-get -y install ettercap-common

ENTRYPOINT tail -f /dev/null