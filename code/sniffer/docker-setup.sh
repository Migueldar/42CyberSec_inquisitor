#!/bin/bash

cd /app/ && apt update && apt install -y libpcap-dev golang git ca-certificates && go mod init test && go get .
