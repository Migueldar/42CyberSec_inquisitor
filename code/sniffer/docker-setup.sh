#!/bin/bash

cd /app && apt update && apt install -y libpcap-dev golang ca-certificates && go get .