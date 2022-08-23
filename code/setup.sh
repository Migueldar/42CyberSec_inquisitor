docker run \
-it \
--rm \
--name test \
-v $(pwd)/sniffer:/app/ \
debian:bullseye-slim \
bash
