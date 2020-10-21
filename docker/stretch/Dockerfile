FROM debian:stretch-slim

WORKDIR acme_dns_tiny

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    python3-minimal python3-dnspython python3-requests \
    python3-coverage \
    && apt-get clean

COPY . .
